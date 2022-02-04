//
//  Sftp.swift
//  mft
//
//  Created by Marcin Labenski on 28/01/2022.
//  Copyright © 2022 Marcin Labenski. All rights reserved.
//

import Foundation
import libssh
import NSString_iconv

@objc public enum MFTKnownHostStatus: Int {
    case KNOWN_HOSTS_ERROR = -2, KNOWN_HOSTS_NOT_FOUND = -1,
    KNOWN_HOSTS_UNKNOWN = 0, KNOWN_HOSTS_OK, KNOWN_HOSTS_CHANGED,
    KNOWN_HOSTS_OTHER,
    NO_SESSION = 100
}

@objcMembers public class MFTFilesystemStats: NSObject {
    public var size:UInt64
    public var freeSpace: UInt64
    init(size: UInt64, freeSpace: UInt64) {
        self.size = size
        self.freeSpace = freeSpace
    }
}

@objc public enum MFTErrorCode: Int {
    case no_error = 0,
         no_session,
         no_pubkey_method,
         no_password_method,
         authentication_failed,
         local_read_error,
         local_write_error,
         local_open_error_for_reading,
         local_open_error_for_writing,
         local_file_not_readable,
         wrong_keyfile,
         canceled = 999
}

@objcMembers public class MFTSftpConnectionInfo: NSObject {
    public var serverBanner = ""
    public var issueBanner = ""
    public var cipherIn = ""
    public var cipherOut = ""
    public var hmacIn = ""
    public var hmacOut = ""
    public var kexAlg = ""
    public var authMethods = [String]()
    public var protocolVerions: Int32 = -1
}

@objcMembers public class MFTSftpConnection: NSObject {

    let hostname: String
    let port: Int
    let username: String
    let password: String
    let prvKeyPath: String
    let prvKey: String
    let passphrase: String
    
    let bufSize = 0x8000
    var sshUserauthNoneCalled = false
    var sshUserauthNoneResult: Int32 = 0
    
    private var session: ssh_session?
    private var sftp_session: sftp_session?
    
    public init(hostname: String, port: Int, username: String, password: String) {
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        
        self.prvKeyPath = ""
        self.prvKey = ""
        self.passphrase = ""
    }
    
    public init(hostname: String, port: Int, username: String,
         prvKeyPath: String, passphrase: String) {
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.prvKeyPath = prvKeyPath
        self.passphrase = passphrase
        
        self.prvKey = ""
        self.password = ""
    }
    
    public init(hostname: String, port: Int, username: String,
         prvKey: String, passphrase: String) {
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.prvKey = prvKey
        self.passphrase = passphrase
        
        self.prvKeyPath = ""
        self.password = ""
    }
    
    deinit {
        disconnect()
        releaseIconv()
    }
    
    // MARK: - Connection, Authentication, Dicsonnection
    
    public var connected: Bool {
        if session != nil {
            return ssh_is_connected(session) == 1
        }
        return false
    }
    
    public func connect() throws {
        try _connect()
    }
    
    func _connect() throws {
        
        session = ssh_new()
        
        if self.username != "" {
            if ssh_options_set(session, SSH_OPTIONS_USER, self.username) < 0 {
                defer {
                    ssh_free(session)
                    session = nil
                }
                throw error_ssh()
            }
        }
        
        if self.port > 0 {
            if ssh_options_set(session, SSH_OPTIONS_PORT_STR, String(self.port)) < 0 {
                defer {
                    ssh_free(session)
                    session = nil
                }
                throw error_ssh()
            }
        }

        if ssh_options_set(session, SSH_OPTIONS_HOST, self.hostname) < 0 {
            defer {
                ssh_free(session)
                session = nil
            }
            throw error_ssh()
        }
        
        let x = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
        x.initialize(to: 0)
        defer {x.deallocate()}
        if ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, x) < 0 {
            defer {
                ssh_free(session)
                session = nil
            }
            throw error_ssh()
        }
        
        if ssh_connect(session) != 0 {
            defer {
                ssh_disconnect(session)
                ssh_free(session)
                session = nil
            }
            throw error_ssh()
        }
    }
    
    public func authenticate() throws {
        
        if session == nil {
            throw error(code: .no_session)
        }
        
        try _authenticate()
        try _sftpSession()
    }
    
    func _intToAuthMethodsList(_ supported: UInt32) -> [String] {
        
        var methods = [String]()
        
        if supported & SSH_AUTH_METHOD_PUBLICKEY != 0 {
            methods.append("publickey")
        }
        if supported & SSH_AUTH_METHOD_PASSWORD != 0 {
            methods.append("password")
        }
        if supported & SSH_AUTH_METHOD_INTERACTIVE != 0 {
            methods.append("keyboard-interactive")
        }
        if supported & SSH_AUTH_METHOD_HOSTBASED != 0 {
            methods.append("hostbased")
        }
        if supported & SSH_AUTH_METHOD_GSSAPI_MIC != 0 {
            methods.append("gssapi-with-mic")
        }
        if supported & SSH_AUTH_METHOD_NONE != 0 {
            methods.append("none")
        }
        if supported  == SSH_AUTH_METHOD_UNKNOWN {
            methods.append("unknown")
        }
        return methods
    }
    
    func _authenticate() throws {
        var auth: Int32;
        
        if sshUserauthNoneCalled == false {
            sshUserauthNoneResult = ssh_userauth_none(session, nil)
            sshUserauthNoneCalled = true
        }
        if sshUserauthNoneResult == 0 {
            // this server allows access without authentication
            return
        }
        let supported = UInt32(ssh_userauth_list(session, nil))
        
        if self.prvKeyPath != "" || self.prvKey != "" {
            
            if supported & SSH_AUTH_METHOD_PUBLICKEY != 0 {
                
                // public key authentication
                auth = try _authenticatePublicKey()
                
            } else {
                ssh_disconnect(session)
                ssh_free(session)
                session = nil
                let msg = String(format: message(forError: .no_pubkey_method),
                                 _intToAuthMethodsList(supported).joined(separator: ","))
                throw error(code: .no_pubkey_method, msg: msg)
            }
        } else {
            
            if supported & SSH_AUTH_METHOD_PASSWORD != 0 {
                
                // password authentication
                auth = ssh_userauth_password(session, nil, self.password)
                
            } else if supported & SSH_AUTH_METHOD_INTERACTIVE != 0 {
                
                // interactive authentication
                auth = try _authenticateInteractive()
                
            } else {
                ssh_disconnect(session)
                ssh_free(session)
                session = nil
                let msg = String(format: message(forError: .no_pubkey_method),
                                 _intToAuthMethodsList(supported).joined(separator: ","))
                throw error(code: .no_password_method, msg: msg)
            }
        }
        
        if auth != SSH_AUTH_SUCCESS.rawValue {
            let err: NSError
            if auth == SSH_AUTH_DENIED.rawValue {
                err = error(code: .authentication_failed)
            } else {
                err = error_ssh()
            }
            ssh_disconnect(session)
            ssh_free(session)
            session = nil
            throw err
        }
    }
    
    func _authenticatePublicKey() throws -> Int32 {
        
        var auth: Int32
        
        let pk = UnsafeMutablePointer<ssh_key?>.allocate(capacity: 1)
        defer {pk.deallocate()}
        
        // make pk based on a file of string
        if self.prvKeyPath != "" {  // from a file
            if FileManager.default.fileExists(atPath: self.prvKeyPath) == false {
                ssh_disconnect(session)
                ssh_free(session)
                session = nil
                throw error(code: .authentication_failed)
            } else {
                auth = ssh_pki_import_privkey_file(self.prvKeyPath, self.passphrase, nil, nil, pk)
            }
        } else { // from memory
            auth = ssh_pki_import_privkey_base64(self.prvKey, self.passphrase, nil, nil, pk)
        }
        
        // authenticate using pk
        if auth == 0 {
            auth = ssh_userauth_publickey(session, nil, pk.pointee)
            ssh_key_free(pk.pointee)
        } else {
            ssh_disconnect(session)
            ssh_free(session)
            session = nil
            throw error(code: .wrong_keyfile)
        }
        
        return auth
    }
    
    func _authenticateInteractive() throws -> Int32 {
        
        var auth = ssh_userauth_kbdint(session, nil, nil)
        if auth == SSH_AUTH_INFO.rawValue {
            //let name = ssh_userauth_kbdint_getname(session)
            //let inst = ssh_userauth_kbdint_getinstruction(session)
            let nprompts = ssh_userauth_kbdint_getnprompts(session)
            if (nprompts == 1) {
                //let echo = UnsafeMutablePointer<Int8>.allocate(capacity: 1)
                //let prompt = ssh_userauth_kbdint_getprompt(session, 0, echo)
                ssh_userauth_kbdint_setanswer(session, 0, self.password)
                auth = ssh_userauth_kbdint(session, nil, nil)
                if auth == SSH_AUTH_INFO.rawValue {
                    // I don't know why, but I have to do it again
                    ssh_userauth_kbdint_setanswer(session, 0, self.password)
                    auth = ssh_userauth_kbdint(session, nil, nil)
                }
            }
        }
        return auth
    }
    
    func _sftpSession() throws {
        
        sftp_session = sftp_new(session)
        
        if sftp_session == nil {
            let err = error_sftp()
            ssh_disconnect(session)
            ssh_free(session)
            session = nil
            throw err
        }
            
        if sftp_init(sftp_session) != 0 {
            let err = error_sftp()
            sftp_free(sftp_session);
            sftp_session = nil
            ssh_disconnect(session)
            ssh_free(session)
            session = nil
            throw err
        }
    }
    
    public func disconnect() {
        
        if sftp_session != nil {
            sftp_free(sftp_session)
            sftp_session = nil
        }
        
        if (session != nil) {
            ssh_disconnect(session)
            ssh_free(session)
            session = nil
        }
    }
    
    public var timeout: Int {
        get {
            if session != nil {
                var buf: UnsafeMutablePointer<Int8>?
                if ssh_options_get(session, SSH_OPTIONS_TIMEOUT, &buf) < 0 {
                    defer { ssh_string_free_char(buf) }
                    let timeoutS = String(cString: buf!)
                    return Int(timeoutS) ?? -1
                }
            }
            return -1
        }
        set {
            if session != nil {
                ssh_options_set(session, SSH_OPTIONS_TIMEOUT, String(newValue))
            }
        }
    }
        
    public func connectionInfo() throws -> MFTSftpConnectionInfo {
    
        if session == nil {
            throw error(code: .no_session)
        }
        
        let ret = MFTSftpConnectionInfo()
        
        if let sbanner = ssh_get_serverbanner(session) {
            ret.serverBanner = stringWith(buf: sbanner)
        }
        if let ibanner = ssh_get_issue_banner(session) {
            ret.issueBanner = stringWith(buf: ibanner)
        }
        
        if let cipher_in = ssh_get_cipher_in(session) {
            ret.cipherIn = String(cString: cipher_in)
        }
        if let cipher_out = ssh_get_cipher_out(session) {
            ret.cipherOut = String(cString: cipher_out)
        }
        if let hmac_in = ssh_get_hmac_in(session) {
            ret.hmacIn = String(cString: hmac_in)
        }
        if let hmac_out = ssh_get_hmac_out(session) {
            ret.hmacOut = String(cString: hmac_out)
        }
        if let kex = ssh_get_kex_algo(session) {
            ret.kexAlg = String(cString: kex)
        }
        
        if sshUserauthNoneCalled == false {
            sshUserauthNoneResult = ssh_userauth_none(session, nil)
            sshUserauthNoneCalled = true
        }
        
        let supported = UInt32(ssh_userauth_list(session, nil))
        ret.authMethods = _intToAuthMethodsList(supported)
        
        ret.protocolVerions = ssh_get_version(session)
        
        return ret;
    }
    
    // MARK: - Directory listing and items info
    
    public func contentsOfDirectory(atPath path: String, maxItems: Int64) throws -> [MFTSftpItem] {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer { pathC.deallocate() }
        let dir = sftp_opendir(sftp_session, pathC)
        if dir == nil {
            throw error_sftp()
        }
        
        var limitReached = false
        var ret = [MFTSftpItem]()
        
        while let file = sftp_readdir(sftp_session, dir) {
            
            if file.pointee.name == nil
                || String(cString: file.pointee.name) == "."
                || String(cString: file.pointee.name) == ".." {
                continue
            }
            
            let item = MFTSftpItem(name: stringWith(buf: file.pointee.name),
                                size: file.pointee.size,
                                uid: file.pointee.uid,
                                gid: file.pointee.gid,
                                owner: stringWith(buf: file.pointee.owner),
                                group: stringWith(buf: file.pointee.group),
                                permissions: file.pointee.permissions,
                                atime: file.pointee.atime,
                                atimeNanos: file.pointee.atime_nseconds,
                                mtime: file.pointee.mtime,
                                mtimeNanos: file.pointee.mtime_nseconds,
                                createTime: file.pointee.createtime,
                                createTimeNanos: file.pointee.createtime_nseconds,
                                isDir: file.pointee.type == SSH_FILEXFER_TYPE_DIRECTORY,
                                isSymlink: file.pointee.type == SSH_FILEXFER_TYPE_SYMLINK,
                                isSpecial: file.pointee.type == SSH_FILEXFER_TYPE_SPECIAL)
            
            ret.append(item)
            if ret.count == maxItems { // note that maxItems == 0 makes this check false
                limitReached = true
                break
            }
        }
        
        if limitReached == false && sftp_dir_eof(dir) == 0 {
            throw error_sftp()
        }

        if sftp_closedir(dir) != 0 {
            throw error_sftp()
        }
        
        return ret
    }
    
    public func infoForFile(atPath: String) throws -> MFTSftpItem {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let path: String
        if atPath == "." {
            let p = sftp_canonicalize_path(sftp_session, ".")
            path = stringWith(buf: p!)
        } else {
            path = atPath
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let file = sftp_stat(sftp_session, pathC) {
            let item = MFTSftpItem(name: path,
                                size: file.pointee.size,
                                uid: file.pointee.uid,
                                gid: file.pointee.gid,
                                owner: "", //String(cString: file.pointee.owner),
                                group: "", //String(cString: file.pointee.group),
                                permissions: file.pointee.permissions,
                                atime: file.pointee.atime,
                                atimeNanos: file.pointee.atime_nseconds,
                                mtime: file.pointee.mtime,
                                mtimeNanos: file.pointee.mtime_nseconds,
                                createTime: file.pointee.createtime,
                                createTimeNanos: file.pointee.createtime_nseconds,
                                isDir: file.pointee.type == SSH_FILEXFER_TYPE_DIRECTORY,
                                isSymlink: file.pointee.type == SSH_FILEXFER_TYPE_SYMLINK,
                                isSpecial: file.pointee.type == SSH_FILEXFER_TYPE_SPECIAL)
            return item
        } else {
            throw error_sftp()
        }
    }
    
    public func effectiveTarget(forPath path:String) throws -> String {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let file = sftp_readlink(sftp_session, pathC) {
            return stringWith(buf: file)
        } else {
            throw error_sftp()
        }
    }
    
    // MARK: - Creating and removing
    
    public func createDirectory(atPath path: String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if sftp_mkdir(sftp_session, pathC, 0o755) < 0 {
            throw error_sftp()
        }
    }
    
    public func createSymbolicLink(atPath path: String, withDestinationPath destPath:String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        let destPathC = cString(for: destPath)
        defer {destPathC.deallocate()}
        
        if sftp_symlink(sftp_session, destPathC, pathC) < 0 {
            throw error_sftp()
        }
    }

    public func removeDirectory(atPath path: String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if sftp_rmdir(sftp_session, pathC) < 0 {
            throw error_sftp()
        }
    }
    
    public func removeFile(atPath path: String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if sftp_unlink(sftp_session, pathC) < 0 {
            throw error_sftp()
        }
    }
    
    // MARK: - Download
    
    public func contents(atPath path: String, toStream outputStream:OutputStream, fromPosition pos:UInt64,
                  progress:((UInt64, UInt64) -> (Bool))?) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let file = sftp_open(sftp_session, pathC, O_RDONLY, 0) {
            defer { sftp_close(file) }
        
            if pos > 0 && sftp_seek64(file, pos) < 0 {
                throw error_sftp()
            }
            
            if outputStream.streamStatus == .notOpen {
                outputStream.open()
            }
            defer { outputStream.close() }
            
            let fileInfo = try infoForFile(atPath: path)
            
            var totalReadCount: UInt64 = pos
            
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
            defer { buf.deallocate() }
            var readCount = sftp_read(file, buf, bufSize)
            while readCount > 0 {
                
                var writeCountLeft = readCount
                var writeCount = 1
                var ptr: Int = 0
                while writeCountLeft > 0 && writeCount > 0 {
                    writeCount = outputStream.write(buf + ptr, maxLength: writeCountLeft)
                    writeCountLeft -= writeCount > 0 ? writeCount : 0
                    ptr += writeCount
                }
                
                if writeCount < 0 || (writeCount == 0 && writeCountLeft > 0) {
                    throw error(code: .local_write_error)
                }
                
                totalReadCount += UInt64(readCount)
                if progress != nil && progress!(totalReadCount, fileInfo.size) == false {
                    throw errorCancelled()
                }
                            
                readCount = sftp_read(file, buf, bufSize)
            }
            
            if readCount < 0 {
                throw error_sftp()
            }
        } else {
            throw error_sftp()
        }
    }

    // MARK: - Upload
    
    public func write(stream inputStream: InputStream, toFileAtPath path: String, append:Bool,
                      progress:((UInt64) -> (Bool))?) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if inputStream.streamStatus == .notOpen {
            inputStream.open()
        }
        
        defer {inputStream.close()}
        
        if inputStream.hasBytesAvailable == false {
            throw error(code: .local_read_error)
        }
        
        
        var flags : Int32 = O_CREAT|O_RDWR;
        if append == false {
            flags |= O_TRUNC
        }
        if let file = sftp_open(sftp_session, pathC, flags, 0o644) {
            defer {
                sftp_close(file)
            }
            
            if append {
                let fileInfo = try infoForFile(atPath: path)
                inputStream.setProperty(fileInfo.size, forKey: .fileCurrentOffsetKey)
                if inputStream.hasBytesAvailable == false {
                    throw error(code: .local_read_error)
                }
                sftp_seek64(file, fileInfo.size)
            }
            
            try _write(stream: inputStream, toFileHandle: file, progress: progress)
            
        } else {
            throw error_sftp()
        }
    }
    
    func _write(stream inputStream: InputStream, toFileHandle file:sftp_file, progress:((UInt64) -> (Bool))?) throws {
            
        var totalWriteCount: UInt64 = 0
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        defer { buf.deallocate() }
        var readCount: Int = -1
        while inputStream.hasBytesAvailable {
            readCount = inputStream.read(buf, maxLength: bufSize)
            if readCount > 0 {
                var writeCount = 1
                var writeCountLeft = readCount
                var ptr: Int = 0
                while writeCountLeft > 0 && writeCount > 0 {
                    writeCount = sftp_write(file, buf + ptr, readCount)
                    writeCountLeft -= writeCount > 0 ? writeCount : 0
                    if writeCount > 0 {
                        ptr += writeCount
                        totalWriteCount += UInt64(writeCount)
                        if progress != nil && progress!(totalWriteCount) == false {
                            throw errorCancelled()
                        }
                    } else {
                        throw error_sftp()
                    }
                }
            }
        }
        if readCount < 0 {
            throw error(code: .local_read_error)
        }
    }
    // MARK: - Copy
    
    public func copyItem(atPath fromPath: String, toFileAtPath toPath:String, progress:((UInt64, UInt64) -> (Bool))?) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let fromPathC = cString(for: fromPath)
        defer {fromPathC.deallocate()}
        
        let toPathC = cString(for: toPath)
        defer {toPathC.deallocate()}
        
        if let fromFile = sftp_open(sftp_session, fromPathC, O_RDONLY, 0) {
            defer {sftp_close(fromFile)}
            
            if let toFile = sftp_open(sftp_session, toPathC, O_CREAT|O_RDWR|O_TRUNC, 0o644) {
                defer {sftp_close(toFile)}
                
                let file = try infoForFile(atPath: fromPath)
                
                var totalReadCount: UInt64 = 0
                var totalWriteCount: UInt64 = 0
                
                let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
                defer { buf.deallocate() }
                
                var readCount = sftp_read(fromFile, buf, bufSize)
                
                while readCount > 0 {
                    
                    totalReadCount += UInt64(readCount)
                    
                    var writeCountLeft = readCount
                    var writeCount = 1
                    var ptr: Int = 0
                    
                    while writeCountLeft > 0 && writeCount > 0 {
                        
                        writeCount = sftp_write(toFile, buf + ptr, writeCountLeft)
                        writeCountLeft -= writeCount > 0 ? writeCount : 0
                        if writeCount > 0 {
                            ptr += writeCount
                            totalWriteCount += UInt64(writeCount)
                            if progress != nil && progress!(totalWriteCount, file.size) == false {
                                throw errorCancelled()
                            }
                        } else if writeCount == 0 && writeCountLeft > 0 {
                            throw error_sftp()
                        }
                    }
                    
                    readCount = sftp_read(fromFile, buf, bufSize)
                }
                
                if readCount < 0 {
                    throw error_sftp()
                }
            }
        }
    }
    
    // MARK: - Move/rename
    
    public func moveItem(atPath: String, toPath:String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let atPathC = cString(for: atPath)
        defer {atPathC.deallocate()}
        
        let toPathC = cString(for: toPath)
        defer {toPathC.deallocate()}
        
        if sftp_rename(sftp_session, atPathC, toPathC) < 0 {
            throw error_sftp()
        }
    }

    // MARK: - Setting attributes
    
    public func set(modificationTime mtime:Date?, accessTime atime:Date?, forPath path:String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        let fileAttrs = sftp_attributes.allocate(capacity: 1)
        defer { fileAttrs.deallocate() }
        fileAttrs.pointee.flags = UInt32(SSH_FILEXFER_ATTR_ACMODTIME)
        if mtime != nil {
            fileAttrs.pointee.mtime = UInt32(mtime!.timeIntervalSince1970)
        } else {
            fileAttrs.pointee.mtime = 0
        }
        if (atime != nil) {
            fileAttrs.pointee.atime = UInt32(atime!.timeIntervalSince1970)
        } else {
            fileAttrs.pointee.atime = 0
        }
        if sftp_setstat(sftp_session, pathC, fileAttrs) < 0 {
            throw error_sftp()
        }
    }
    
    public func set(permissions:UInt32, forPath path:String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        let fileAttrs = sftp_attributes.allocate(capacity: 1)
        defer { fileAttrs.deallocate() }
        fileAttrs.pointee.permissions = permissions
        fileAttrs.pointee.flags = UInt32(SSH_FILEXFER_ATTR_PERMISSIONS)
        if sftp_setstat(sftp_session, pathC, fileAttrs) < 0 {
            throw error_sftp()
        }
    }

    // MARK: - Filesystem info
    
    public func filesystemStats(forPath path: String) throws -> MFTFilesystemStats {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let stat = sftp_statvfs(sftp_session, pathC) {
            
            let size = UInt64(stat.pointee.f_frsize * stat.pointee.f_blocks)
            let freeSpace = UInt64(stat.pointee.f_bavail * stat.pointee.f_frsize)
            return MFTFilesystemStats(size: size, freeSpace: freeSpace)
            
        } else {
            throw error_sftp()
        }
    }
    
    // MARK: - Knownhost
    
    public func knownHostStatus(inFile path:String) -> MFTKnownHostStatus {
     
        if session == nil {
            return .NO_SESSION
        }
        
        var entry: UnsafeMutablePointer<ssh_knownhosts_entry>?
        let res = ssh_session_get_known_hosts_entry_file(session, path, &entry)
        defer {
            if entry != nil {
                ssh_knownhosts_entry_free(entry)
            }
        }
        return MFTKnownHostStatus(rawValue: Int(res.rawValue)) ?? .KNOWN_HOSTS_UNKNOWN
    }
    
    public func addKnownHostName(toFile path: String) throws {
    
        if session == nil {
            throw error(code: .no_session)
        }
        
        if knownHostStatus(inFile: path) != .KNOWN_HOSTS_OK {
            var entry: UnsafeMutablePointer<Int8>?
            if ssh_session_export_known_hosts_entry(session, &entry) == 0 {
                defer { ssh_string_free_char(entry) }
                let s = String(cString: entry!)
                if let ostream = OutputStream(toFileAtPath: path, append: true) {
                    ostream.open()
                    defer { ostream.close() }
                    if ostream.write([UInt8](s.utf8), maxLength: s.count) > 0 {
                        // done OK
                        return
                    }
                    throw error(code: .local_write_error)
                }
            }
            throw error_ssh()
        }
    }
    
    public func fingerprintHash() throws -> String {
        
        if session == nil {
            throw error(code: .no_session)
        }
        
        var key: ssh_key?
        if ssh_get_server_publickey(session, &key) == 0 {
            defer { ssh_key_free(key) }
            var pkHash: UnsafeMutablePointer<UInt8>?
            var hashLen: Int = 0
            if ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_MD5, &pkHash, &hashLen) == 0 {
                defer { ssh_clean_pubkey_hash(&pkHash) }
                if let hexa = ssh_get_hexa(pkHash, hashLen) {
                    let hexaS = String(cString: hexa)
                    ssh_string_free_char(hexa)
                    return hexaS
                }
            }
            return ""
        }
        return ""
    }

    
    // MARK: - Auxilary convinience functions
    
    public func resumeFile(atPath path: String, toFileAtPath:String, progress:((UInt64) -> (Bool))?) throws {
        if FileManager.default.isReadableFile(atPath: path) == false {
            throw error(code: .local_file_not_readable)
        }
        let istream = InputStream(fileAtPath: path)
        if istream == nil {
            throw error(code: .local_open_error_for_reading)
        }
        try write(stream: istream!, toFileAtPath: toFileAtPath, append: true, progress: progress)
    }
    
    public func writeFile(atPath path: String, toFileAtPath:String, progress:((UInt64) -> (Bool))?) throws {
        if FileManager.default.isReadableFile(atPath: path) == false {
            throw error(code: .local_file_not_readable)
        }
        let istream = InputStream(fileAtPath: path)
        if istream == nil {
            throw error(code: .local_open_error_for_writing)
        }
        try write(stream: istream!, toFileAtPath: toFileAtPath, append: false, progress: progress)
    }

    // MARK: - Errors
    
    func error_ssh() -> NSError {
        let msg = String(cString: ssh_get_error(UnsafeMutableRawPointer(session!))!)
        let code = ssh_get_error_code(UnsafeMutableRawPointer(session!))
        return NSError(domain: "ssh", code: Int(code), userInfo: [NSLocalizedDescriptionKey: msg])
    }
    
    func error_sftp() -> NSError {
        let msg = String(cString: ssh_get_error(UnsafeMutableRawPointer(session!))!)
        let code = sftp_get_error(sftp_session)
        return NSError(domain: "sftp", code: Int(code), userInfo: [NSLocalizedDescriptionKey: msg])
    }
    
    func error(code: MFTErrorCode) -> NSError {
        let msg = message(forError: code)
        return error(code: code, msg: msg)
    }
    
    func error(code: MFTErrorCode, msg: String) -> NSError {
        return NSError(domain: "mft", code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: msg])
    }
    
    func errorCancelled() -> NSError {
        return error(code: .canceled)
    }
    
    func message(forError error: MFTErrorCode) -> String {
        
        func NSLocalizedString(_ key: String, comment: String) -> String {
            return Bundle(for: MFTSftpConnection.self).localizedString(forKey: key, value: "", table: nil)
        }
        
        switch error {
            
        case .no_session:
            return NSLocalizedString("No SFTP session", comment: "")
            
        case .authentication_failed:
            return NSLocalizedString("Authentication failed", comment: "")
            
        case .no_pubkey_method:
            return NSLocalizedString("Authentication failed. This server does not support publickey authentication. Supported methods: %@.", comment: "")
            
        case .no_password_method:
            return NSLocalizedString("Authentication failed. This server does not support password authentication. Supported methods: %@.", comment: "")
            
        case .local_read_error:
            return NSLocalizedString("Read error", comment: "")
            
        case .local_write_error:
            return NSLocalizedString("Write error", comment: "")
            
        case .local_open_error_for_reading:
            return NSLocalizedString("Unable to open the input stream", comment: "")
            
        case .local_open_error_for_writing:
            return NSLocalizedString("Unable to open the output stream", comment: "")
            
        case .local_file_not_readable:
            return NSLocalizedString("You don't have permission to read the file", comment: "")
            
        case .wrong_keyfile:
            return NSLocalizedString("Wrong keyfile format or wrong passphrase", comment: "")
            
        case .canceled:
            return NSLocalizedString("Canceled", comment: "")
            
        default:
            return NSLocalizedString("Error", comment: "")
        }
    }
    
    // MARK: - Encoding conversion
    
    var convNil: iconv_t = iconv_t.init(bitPattern: -1)!
    var convToUtf8: iconv_t = iconv_t.init(bitPattern: -1)!
    var convFromUtf8: iconv_t = iconv_t.init(bitPattern: -1)!
    var _encoding: String?
    
    public var encoding: String? {
        get {
            return _encoding
        }
        set {
            if newValue != _encoding {
                _encoding = newValue
                if convToUtf8 != convNil {
                    iconv_close(convToUtf8)
                }
                if convFromUtf8 != convNil {
                    iconv_close(convFromUtf8)
                }
                if _encoding != nil {
                    convToUtf8 = iconv_open("UTF-8-MAC", _encoding!)
                    convFromUtf8 = iconv_open(_encoding!, "UTF-8-MAC")
                } else {
                    convToUtf8 = convNil
                    convFromUtf8 = convNil
                }
            }
        }
    }
    
    func releaseIconv() {
        if convToUtf8 != convNil {
            iconv_close(convToUtf8)
        }
        convToUtf8 = convNil
        if convFromUtf8 != convNil {
            iconv_close(convFromUtf8)
        }
        convFromUtf8 = convNil
    }
    
    func cString(for s: String) -> UnsafePointer<CChar> {
        let buf = UnsafeMutablePointer<CChar>.allocate(capacity: s.convBufSize())
        return (s as NSString).toBuf(buf, bufLenght: s.convBufSize(), iconvFromUtf8: convFromUtf8)
    }
    
    func stringWith(buf: UnsafePointer<CChar>) -> String {
        return NSString(buf: buf, iconvToUtf8: convToUtf8) as String
    }
}
