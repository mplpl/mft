//
//  mftBenchTests.swift
//  mftTests
//
//  Created by Marcin Labenski on 15/08/2024.
//  Copyright © 2024 Marcin Labenski. All rights reserved.
//

import XCTest
@testable import mft

class mftBenchTests: XCTestCase {
    
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
        
    func testBenchDownload() throws {
        let srcTestFile = "/tmp/mft/src_download_test_big"
        let destTestFile = "/tmp/mft/dest_download_test_big"
        let data = NSMutableData()
        
        data.length = 1024 * 1024 * 1024
        try data.write(toFile: srcTestFile)
        
        let outStream = OutputStream(toFileAtPath: destTestFile, append: false)
        XCTAssert(outStream != nil)
        
        let start = DispatchTime.now().uptimeNanoseconds
            
        XCTAssertNoThrow(try sftp.contents(atPath: srcTestFile, toStream: outStream!, fromPosition: 0) {
            downloaded, total in
            return true
        })
        
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
        let rate = Double(data.length) / elapsed / (1024*1024)
        NSLog("Download time: %d s, speed %f MB/s", Int(elapsed) as Int, rate)
        XCTAssert(rate > 200.0)
        
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: srcTestFile) as NSDictionary
        let destAttrs = try FileManager.default.attributesOfItem(atPath: destTestFile) as NSDictionary
        
        XCTAssert(srcAttrs.fileSize() == destAttrs.fileSize())
        XCTAssert(srcTestFile.md5() == destTestFile.md5())
    }
    
    func testBenchUpload() throws {
        let srcTestFile = "/tmp/mft/src_upload_test_big"
        let destTestFile = "/tmp/mft/dest_upload_test_big"
        let data = NSMutableData()
        
        data.length = 1024 * 1024 * 1024
        try data.write(toFile: srcTestFile)
        
        let inStream = InputStream(fileAtPath: srcTestFile)
        XCTAssert(inStream != nil)
        
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: srcTestFile) as NSDictionary
        
        let start = DispatchTime.now().uptimeNanoseconds
        
        XCTAssertNoThrow(try sftp.write(stream: inStream!, toFileAtPath: destTestFile, append: false) { uploaded in
            return true
        })
        
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
        let rate = Double(data.length) / elapsed / (1024*1024)
        NSLog("Upload time: %d s, speed %f MB/s", Int(elapsed) as Int, rate)
        XCTAssert(rate > 200.0)
        
        let destAttrs = try FileManager.default.attributesOfItem(atPath: destTestFile) as NSDictionary
        XCTAssert(srcAttrs.fileSize() == destAttrs.fileSize())
        XCTAssert(destTestFile.md5() == srcTestFile.md5())
    }
    
    func testBenchCopy() throws {
        let srcTestFile = "/tmp/mft/src_upload_test_big"
        let destTestFile = "/tmp/mft/dest_upload_test_big"
        let data = NSMutableData()
        
        data.length = 1024 * 1024 * 1024
        try data.write(toFile: srcTestFile)
        
        let srcAttrs = try FileManager.default.attributesOfItem(atPath: srcTestFile) as NSDictionary
        
        let start = DispatchTime.now().uptimeNanoseconds
        
        XCTAssertNoThrow(try sftp.copyItem(atPath: srcTestFile, toFileAtPath: destTestFile, progress: { _, _ in
            return true
        }))
        
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
        let rate = Double(data.length) / elapsed / (1024*1024)
        NSLog("Copy time: %d s, speed %f MB/s", Int(elapsed) as Int, rate)
        // copyItem does not use async io and so it is slow for now
        XCTAssert(rate > 40.0)
        
        let destAttrs = try FileManager.default.attributesOfItem(atPath: destTestFile) as NSDictionary
        XCTAssert(srcAttrs.fileSize() == destAttrs.fileSize())
        XCTAssert(destTestFile.md5() == srcTestFile.md5())
    }
}
