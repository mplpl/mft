//
//  mftFunctionalTests.swift
//  mftTests
//
//  Created by Marcin Labenski on 28/01/2022.
//  Copyright © 2022-2024 Marcin Labenski. All rights reserved.
//

import XCTest
@testable import mft

class mftFunctionalTests: XCTestCase {
    
    var sftp: MFTSftpConnection!
    var username = NSUserName()

    override func setUpWithError() throws {
        try FileManager.default.createDirectory(atPath: "/tmp/mft", withIntermediateDirectories: true, attributes: [:])
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                                 port: 22,
                                 username: self.username,
                                 prvKeyPath: NSHomeDirectory() + "/.ssh/id_rsa",
                                 passphrase: "")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertNoThrow(try sftp.authenticate())
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(atPath: "/tmp/mft")
    }
    
    func testConnect() throws {
        XCTAssert(sftp.connected)
        sftp.disconnect()
        XCTAssert(sftp.connected == false)
    }
    
    func testConnectFailed() throws {
        sftp = MFTSftpConnection(hostname: "127.0.0.222",
                              port: 22,
                              username: self.username,
                              prvKeyPath: NSHomeDirectory() + "/.ssh/id_rsaXXXX",
                              passphrase: "")
        XCTAssertThrowsError(try sftp.connect())
    }

    func testAuthFailed() throws {
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: NSHomeDirectory() + "/.ssh/id_rsaXXXX",
                              passphrase: "")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertThrowsError(try sftp.authenticate())
    }
    
    func testAuthKeyPassphrase() throws {
        // for this test to work:
        // ssh-keygen ssh-keygen -C "foo@bar.baz” /Users/username/.ssh/id_rsa_pass
        // type 'test' when asked for passphrase
        // ssh-copy-id -i /Users/username/.ssh/id_rsa_pass username@127.0.0.1
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: NSHomeDirectory() + "/.ssh/id_rsa_pass",
                              passphrase: "test")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertNoThrow(try sftp.authenticate())
    }
    
    func testAuthKeyPassphraseWrongFile() throws {
        let testItem = "/tmp/mft/fake_key"
        FileManager.default.createFile(atPath: testItem, contents: nil, attributes: [:])
        
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: testItem,
                              passphrase: "aaaa")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertThrowsError(try sftp.authenticate())
    }
    
    func testAuthKeyPassphraseNoFile() throws {
        let testItem = "/tmp/mft/fake_key"
        
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: testItem,
                              passphrase: "aaaa")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertThrowsError(try sftp.authenticate())
    }
    
    func testAuthKeyPassphraseNoPassphraseGiven() throws {
        // for this test to work:
        // ssh-keygen ssh-keygen -C "foo@bar.baz” /Users/username/.ssh/id_rsa_pass
        // type 'test' when asked for passphrase
        // ssh-copy-id -i /Users/username/.ssh/id_rsa_pass username@127.0.0.1
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: NSHomeDirectory() + "/.ssh/id_rsa_pass",
                              passphrase: "")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertThrowsError(try sftp.authenticate())
    }
    
    func testAuthKeyPassphraseWrongPassphrase() throws {
        // for this test to work:
        // ssh-keygen ssh-keygen -C "foo@bar.baz” /Users/username/.ssh/id_rsa_pass
        // type 'test' when asked for passphrase
        // ssh-copy-id -i /Users/username/.ssh/id_rsa_pass username@127.0.0.1
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: NSHomeDirectory() + "/.ssh/id_rsa_pass",
                              passphrase: "aaaaa")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertThrowsError(try sftp.authenticate())
    }
    
    func testAuthKeyEd25519() throws {
        // for this test to work:
        // ssh-keygen ssh-keygen -t ed25519 -C "foo@bar.baz” /Users/username/.ssh/id_ed25519
        // type 'test' when asked for passphrase
        // ssh-copy-id -i /Users/username/.ssh/id_ed25519 username@127.0.0.1
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKeyPath: NSHomeDirectory() + "/.ssh/id_ed25519",
                              passphrase: "test")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertNoThrow(try sftp.authenticate())
    }
    
    func testList() throws {
        var items: [MFTSftpItem] = []
        XCTAssertNoThrow(items = try sftp.contentsOfDirectory(atPath: "/tmp", maxItems: 0))
        _print(items: items)
    }
    
    func _print(items: [MFTSftpItem]) {
        for item in items {
            NSLog("%@ %d %@ %d %@ %o %d %d %d %lld %@",
                  item.mtime.description,
                  item.uid, item.owner, item.gid, item.group,
                  item.permissions,
                  item.isDirectory, item.isSymlink, item.isSpecial,
                  item.size, item.filename)
        }
    }

    func testDownload() throws {
        let testItem = "/tmp/mft/download_test"
        let srcItem = "/usr/bin/ssh"
        
        let outStream = OutputStream(toFileAtPath: testItem, append: false)
        XCTAssert(outStream != nil)
        
        XCTAssertNoThrow(try sftp.contents(atPath: srcItem, toStream: outStream!, fromPosition: 0) {
            downloaded, total in
            
            NSLog("%d / %d", downloaded, total)
            return true
        })
        
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: srcItem) as NSDictionary
        let destAttrs = try FileManager.default.attributesOfItem(atPath: testItem) as NSDictionary
        
        XCTAssert(srcAttrs.fileSize() == destAttrs.fileSize())
        XCTAssert(testItem.md5() == srcItem.md5())
    }
    
    func testDownloadWithResume() throws {
        let testItem = "/tmp/mft/downloadr_test"
        let srcItem = "/usr/bin/ssh"
        
        let outStream2 = OutputStream(toFileAtPath: testItem, append: false)
        XCTAssert(outStream2 != nil)
        
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: srcItem) as NSDictionary
        
        XCTAssertNoThrow(try sftp.contents(atPath: srcItem, toStream: outStream2!, fromPosition: srcAttrs.fileSize() - 100) {
            downloaded, total in
            
            NSLog("%d / %d", downloaded, total)
            return true
        })
        
        let destAttrs = try FileManager.default.attributesOfItem(atPath: testItem) as NSDictionary
        XCTAssert(destAttrs.fileSize() == 100)
    }
    
    func testUpload() throws {
        let testItem = "/tmp/mft/upload_test"
        let srcItem = "/usr/bin/ssh"
     
        let inStream = InputStream(fileAtPath: srcItem)
        XCTAssert(inStream != nil)
        
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: srcItem) as NSDictionary
        
        XCTAssertNoThrow(try sftp.write(stream: inStream!, toFileAtPath: testItem, append: false) { uploaded in
            NSLog("%d / %d", uploaded, srcAttrs.fileSize())
            return true
        })
        
        let destAttrs = try FileManager.default.attributesOfItem(atPath: testItem) as NSDictionary
        XCTAssert(srcAttrs.fileSize() == destAttrs.fileSize())
        XCTAssert(testItem.md5() == srcItem.md5())
    }
    
    func testMkdir() throws {
        let testItem = "/tmp/mft/mkdir_test"
        XCTAssertNoThrow(try sftp.createDirectory(atPath: testItem))
        XCTAssert(FileManager.default.fileExists(atPath: testItem))
    }
    
    func testRmdir() throws {
        let testItem = "/tmp/mft/rmdir_test"
        
        try FileManager.default.createDirectory(atPath: testItem, withIntermediateDirectories: true, attributes: [:])
        XCTAssert(FileManager.default.fileExists(atPath: testItem))
        
        XCTAssertNoThrow(try sftp.removeDirectory(atPath: testItem))
        XCTAssert(FileManager.default.fileExists(atPath: testItem) == false)
    }
    
    func testRm() throws {
        let testItem = "/tmp/mft/rm_test"
        
        FileManager.default.createFile(atPath: testItem, contents: nil, attributes: [:])
        
        XCTAssert(FileManager.default.fileExists(atPath: testItem))
        
        XCTAssertNoThrow(try sftp.removeFile(atPath: testItem))
        XCTAssert(FileManager.default.fileExists(atPath: testItem) == false)
    }
    
    func testLn() throws {
        let testItem = "/tmp/mft/ln_test"
        let testItemDest = "/tmp/mft/ln_test_dest"
        
        FileManager.default.createFile(atPath: testItemDest, contents: nil, attributes: [:])
        XCTAssert(FileManager.default.fileExists(atPath: testItemDest))
        XCTAssert(FileManager.default.fileExists(atPath: testItem) == false)
        
        XCTAssertNoThrow(try sftp.createSymbolicLink(atPath: testItem, withDestinationPath: testItemDest))
        XCTAssert(FileManager.default.fileExists(atPath: testItem))
    }
    
    func testLnRelative() throws {
        let testItem = "/tmp/mft/lnr_test"
        let testItemDest = "/tmp/mft/lnr_test_dest"
        
        FileManager.default.createFile(atPath: testItemDest, contents: nil, attributes: [:])
        XCTAssert(FileManager.default.fileExists(atPath: testItemDest))
        XCTAssert(FileManager.default.fileExists(atPath: testItem) == false)
        
        XCTAssertNoThrow(try sftp.createSymbolicLink(atPath: testItem, withDestinationPath: "lnr_test_dest"))
        XCTAssert(FileManager.default.fileExists(atPath: testItem))
    }
    
    func testMoveDir() throws {
        let testItemSrc = "/tmp/mft/mvd_test_src"
        let testItemDest = "/tmp/mft/mvd_test_dest"
        
        try FileManager.default.createDirectory(atPath: testItemSrc, withIntermediateDirectories: true, attributes: [:])
        
        XCTAssertNoThrow(try sftp.moveItem(atPath: testItemSrc, toPath: testItemDest))
        XCTAssert(FileManager.default.fileExists(atPath: testItemSrc) == false)
        XCTAssert(FileManager.default.fileExists(atPath: testItemDest))
    }
    
    func testMoveFile() throws {
        let testItemSrc = "/tmp/mft/mvf_test_src"
        let testItemDest = "/tmp/mft/mvf_test_dest"
        FileManager.default.createFile(atPath: testItemSrc, contents: nil, attributes: [:])
        XCTAssertNoThrow(try sftp.moveItem(atPath: testItemSrc, toPath: testItemDest))
        XCTAssert(FileManager.default.fileExists(atPath: testItemSrc) == false)
        XCTAssert(FileManager.default.fileExists(atPath: testItemDest))
    }
    
    func testSetModTime() throws {
        let testItem = "/tmp/mft/mtime_test"
        FileManager.default.createFile(atPath: testItem, contents: nil, attributes: [:])
        let mtime = Date(timeIntervalSinceReferenceDate: 123456789.0)
        XCTAssertNoThrow(try sftp.set(modificationTime: mtime, accessTime: nil, forPath: testItem))
        let destAttrs = try FileManager.default.attributesOfItem(atPath: testItem) as NSDictionary
        XCTAssert(destAttrs.fileModificationDate() == mtime)
    }
    
    func testSetPermissions() throws {
        let testItem = "/tmp/mft/perms_test"
        FileManager.default.createFile(atPath: testItem, contents: nil, attributes: [:])
        let permToSet: UInt32 = 0o666
        XCTAssertNoThrow(try sftp.set(permissions: permToSet, forPath:testItem))
        let destAttrs = try FileManager.default.attributesOfItem(atPath: testItem) as NSDictionary
        XCTAssert(destAttrs.filePosixPermissions() == permToSet)
    }
    
    func testKnownHostsStatus() throws {
        XCTAssert(sftp.knownHostStatus(inFile: "/tmp/mft/known_hosts") != .KNOWN_HOSTS_OK)
        XCTAssertNoThrow(try sftp.addKnownHostName(toFile: "/tmp/mft/known_hosts"))
        XCTAssert(sftp.knownHostStatus(inFile: "/tmp/mft/known_hosts") == .KNOWN_HOSTS_OK)
    }
    
    func testFingerprintHash() throws {
        XCTAssertNoThrow(try sftp.fingerprintHash())
    }
    
    func testCopy() throws {
        let testItemSrc = "/tmp/mft/copy_test_src"
        let testItemDest = "/tmp/mft/copy_test_dest"
        let data = Data(repeating: 9, count: 20000000)
        FileManager.default.createFile(atPath: testItemSrc, contents: data, attributes: [:])
        XCTAssertNoThrow(try sftp.copyItem(atPath: testItemSrc, toFileAtPath: testItemDest) { copied, total in
            NSLog("%d / %d", copied, total)
            return true
        })
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: testItemSrc) as NSDictionary
        let destAttrs = try FileManager.default.attributesOfItem(atPath: testItemDest) as NSDictionary
        
        XCTAssert(srcAttrs.fileSize() == destAttrs.fileSize())
        XCTAssert(testItemSrc.md5() == testItemDest.md5())
    }
    
    func testEncodingSet() throws {
        sftp.encoding = "ISO8859-2"
        XCTAssert(sftp.convFromUtf8 != sftp.convNil)
        XCTAssert(sftp.convToUtf8 != sftp.convNil)
        sftp.releaseIconv()
        XCTAssert(sftp.convFromUtf8 == sftp.convNil)
        XCTAssert(sftp.convToUtf8 == sftp.convNil)
        sftp.encoding = "XXXXXX"
        XCTAssert(sftp.convFromUtf8 == sftp.convNil)
        XCTAssert(sftp.convToUtf8 == sftp.convNil)
        sftp.releaseIconv()
    }
    
    func testUploadNoR() throws {
        let testItemSrc = "/tmp/mft/upload_test_no_r_src"
        let testItemDest = "/tmp/mft/upload_test_no_r_dest"
        let data = Data(repeating: 9, count: 2000000)
        FileManager.default.createFile(atPath: testItemSrc, contents: data, attributes: [.posixPermissions:0o0])
        
        XCTAssertThrowsError(try sftp.uploadFile(atPath: testItemSrc, toFileAtPath: testItemDest, progress: { uploaded in
            return true
        }))
    }
    
    func testResumeNoR() throws {
        let testItemSrc = "/tmp/mft/upload_test_no_r_src"
        let testItemDest = "/tmp/mft/upload_test_no_r_dest"
        let data = Data(repeating: 9, count: 2000000)
        FileManager.default.createFile(atPath: testItemSrc, contents: data, attributes: [.posixPermissions:0o0])
        
        XCTAssertThrowsError(try sftp.resumeUploadFile(atPath: testItemSrc, toFileAtPath: testItemDest, progress: { uploaded in
            return true
        }))
    }
    
    func testUploadEmptyFile() throws {
        let testItemSrc = "/tmp/mft/upload_test_empty_src"
        let testItemDest = "/tmp/mft/upload_test_empty_dest"
        FileManager.default.createFile(atPath: testItemSrc, contents: nil, attributes: [:])
        
        XCTAssertNoThrow(try sftp.uploadFile(atPath: testItemSrc, toFileAtPath: testItemDest, progress: { uploaded in
            return true
        }))
    }
    
    func testConnectionInfo() throws {
        var info = MFTSftpConnectionInfo()
        XCTAssertNoThrow(info = try sftp.connectionInfo())
        NSLog("Protocol version: %d", info.protocolVerions)
        NSLog("Auth methods: %@", info.authMethods.joined(separator: ","))
        NSLog("Server banner: %@", info.serverBanner)
        NSLog("Issue banner: %@", info.issueBanner)
        NSLog("Cipher in: %@ out: %@", info.cipherIn, info.cipherOut)
        NSLog("HMAC in: %@ out: %@", info.hmacIn, info.hmacOut)
        NSLog("KEX alg: %@", info.kexAlg)
        NSLog("Max Handlers: %d", info.maxOpenHandles);
        NSLog("Max Packet Len: %d", info.maxPacketLenght);
        NSLog("Max Read Len: %d", info.maxReadLenght);
        NSLog("Max Write Len: %d", info.maxWriteLenght);
    }
    
    func testListWithLimit() throws {
        let testItemSrc = "/tmp/mft/upload_list_test"
        try FileManager.default.createDirectory(atPath: testItemSrc, withIntermediateDirectories: true, attributes: [:])
        for i in 0...10 {
            FileManager.default.createFile(atPath: testItemSrc + "/file_" + String(i), contents: nil, attributes: [:])
        }
        var items = [MFTSftpItem]()
        XCTAssertNoThrow(items = try sftp.contentsOfDirectory(atPath: testItemSrc, maxItems: 5))
        XCTAssert(items.count == 5)
    }
    
    func testAuthWithPkInString() throws {
        
        let pk = try String(contentsOfFile: NSHomeDirectory() + "/.ssh/id_rsa")
   
        sftp = MFTSftpConnection(hostname: "127.0.0.1",
                              port: 22,
                              username: self.username,
                              prvKey: pk,
                              passphrase: "")
        XCTAssertNoThrow(try sftp.connect())
        XCTAssertNoThrow(try sftp.authenticate())
        
    }
        
    func testReadlink() throws {
        let testItemFile = "/tmp/mft/readlink_file"
        let testItemLink = "/tmp/mft/readlink_link"
        FileManager.default.createFile(atPath: testItemFile, contents: nil, attributes: [:])
        try FileManager.default.createSymbolicLink(atPath: testItemLink, withDestinationPath: testItemFile)
        XCTAssert(try sftp.effectiveTarget(forPath: testItemLink) == testItemFile)
    }
    
    func testUploadResume() throws {
        let testSrc = "/tmp/mft/upload_resume_src"
        let testDest = "/tmp/mft/upload_resume_dest"
        let data = Data(repeating: 9, count: 2000000)
        FileManager.default.createFile(atPath: testDest, contents: data, attributes: [:])
        let data2 = Data(repeating: 8, count: 2000000)
        let data3 = data + data2
        FileManager.default.createFile(atPath: testSrc, contents: data3, attributes: [:])
        var uploadStartAt:UInt64 = 0
        XCTAssertNoThrow(try sftp.resumeUploadFile(atPath: testSrc, toFileAtPath: testDest) { uploaded in
            if uploadStartAt == 0 {
                uploadStartAt = uploaded
            }
            return true
        })
        XCTAssert(uploadStartAt < 3000000) // ~ 2000000+bufferSize
        let attrs = try FileManager.default.attributesOfItem(atPath: testDest) as NSDictionary
        XCTAssert(attrs.fileSize() == 4000000)
        XCTAssert(testSrc.md5() == testDest.md5())
    }
    
    func testUploadOverwrite() throws {
        let testSrc = "/tmp/mft/overwrite_src"
        let testDest = "/tmp/mft/overwrite_dest"
        let data = Data(repeating: 9, count: 2000000)
        FileManager.default.createFile(atPath: testDest, contents: data, attributes: [:])
        let data2 = Data(repeating: 8, count: 2000000)
        let data3 = data + data2
        FileManager.default.createFile(atPath: testSrc, contents: data3, attributes: [:])
        var uploadStartAt:UInt64 = 0
        XCTAssertNoThrow(try sftp.uploadFile(atPath: testSrc, toFileAtPath: testDest) { uploaded in
            NSLog("%d", uploaded)
            if uploadStartAt == 0 {
                uploadStartAt = uploaded
            }
            return true
        })
        XCTAssert(uploadStartAt < 1000000) // ~ bufferSize
        let attrs = try FileManager.default.attributesOfItem(atPath: testDest) as NSDictionary
        XCTAssert(attrs.fileSize() == 4000000)
        XCTAssert(testSrc.md5() == testDest.md5())
    }
    
    func testDownloadResume() throws {
        let testSrc = "/tmp/mft/download_resume_src"
        let testDest = "/tmp/mft/download_resume_dest"
        let data = Data(repeating: 9, count: 2000000)
        FileManager.default.createFile(atPath: testDest, contents: data, attributes: [:])
        let data2 = Data(repeating: 8, count: 2000000)
        let data3 = data + data2
        FileManager.default.createFile(atPath: testSrc, contents: data3, attributes: [:])
        var downloadStartAt:UInt64 = 0
        XCTAssertNoThrow(try sftp.resumeDownloadFile(atPath: testSrc, toFileAtPath: testDest, progress: {
            downloaded, total in
            
            if downloadStartAt == 0 {
                downloadStartAt = downloaded
            }
            return true
        }))
        XCTAssert(downloadStartAt < 3000000)  // ~ 2000000+bufferSize
        let attrs = try FileManager.default.attributesOfItem(atPath: testDest) as NSDictionary
        XCTAssert(attrs.fileSize() == 4000000)
        XCTAssert(testSrc.md5() == testDest.md5())
    }
    
    func testDownloadOverwrite() throws {
        let testSrc = "/tmp/mft/download_resume_src"
        let testDest = "/tmp/mft/download_resume_dest"
        let data = Data(repeating: 9, count: 2000000)
        FileManager.default.createFile(atPath: testDest, contents: data, attributes: [:])
        let data2 = Data(repeating: 8, count: 2000000)
        let data3 = data + data2
        FileManager.default.createFile(atPath: testSrc, contents: data3, attributes: [:])
        var downloadStartAt:UInt64 = 0
        XCTAssertNoThrow(try sftp.downloadFile(atPath: testSrc, toFileAtPath: testDest, progress: {
            downloaded, total in
            
            if downloadStartAt == 0 {
                downloadStartAt = downloaded
            }
            return true
        }))
        XCTAssert(downloadStartAt < 1000000) // ~ bufferSize
        let attrs = try FileManager.default.attributesOfItem(atPath: testDest) as NSDictionary
        XCTAssert(attrs.fileSize() == 4000000)
        XCTAssert(testSrc.md5() == testDest.md5())
    }
}
