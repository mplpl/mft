//
//  Sftp.swift
//  mft
//
//  Created by Marcin Labenski on 28/01/2022.
//  Copyright © 2022-2025 Marcin Labenski. All rights reserved.
//

import Foundation
@_implementationOnly import libssh
@_implementationOnly import NSString_iconv

/// Status of the hosts.
@objc public enum MFTKnownHostStatus: Int {
    case KNOWN_HOSTS_ERROR = -2, KNOWN_HOSTS_NOT_FOUND = -1,
    KNOWN_HOSTS_UNKNOWN = 0, KNOWN_HOSTS_OK, KNOWN_HOSTS_CHANGED,
    KNOWN_HOSTS_OTHER,
    NO_SESSION = 100
}

/// File system statistics.
@objcMembers public class MFTFilesystemStats: NSObject {
    public var size:UInt64
    public var freeSpace: UInt64
    init(size: UInt64, freeSpace: UInt64) {
        self.size = size
        self.freeSpace = freeSpace
    }
}

/// Error codes used in NSError objects reported by methods of MFTSftpConnectionInfo class.
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
         local_file_not_writable,
         wrong_keyfile,
         file_not_found,
         canceled = 999
}

/// SFTP connection information
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
    public var maxOpenHandles: UInt64 = 0
    public var maxPacketLenght: UInt64 = 0
    public var maxReadLenght: UInt64 = 0
    public var maxWriteLenght: UInt64 = 0
}

/// The class represents a single SFTP connection. It contains method for establishing connections,
/// authenticating on the server as well as methods for items manipulation (like uploading, downloading,
/// removing, creating, ...).
/// The objects of this class are NOT thread safe and must NOT be used to running multiple operations
/// at the same time. If you need such functionality, create multiple MFTSftpConnection (and by doing that
/// establish multiple SFTP connections).
@objcMembers public class MFTSftpConnection: NSObject {

    let hostname: String
    let port: Int
    let username: String
    let password: String
    let prvKeyPath: String
    let prvKey: String
    let passphrase: String
    let sshAgentSocketPath: String
    
    var sshUserauthNoneCalled = false
    var sshUserauthNoneResult: Int32 = 0
    public var defRqCount = 20
    var defChunkSize: UInt64 = 0xF000
    
    private var session: ssh_session?
    private var sftp_session: sftp_session?
    
    /// Create a new connection with password based authentication data.
    /// - Parameters:
    ///     - hostname: The SFTP server hostname.
    ///     - port: The SFTP server port name.
    ///     - username: The user name to authenticate as.
    ///     - password: The user password.
    public init(hostname: String, port: Int, username: String, password: String) {
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        
        self.prvKeyPath = ""
        self.prvKey = ""
        self.passphrase = ""
        self.sshAgentSocketPath = ""
    }
    
    /// Create a new connection with public key based authentication data read from a file.
    /// - Parameters:
    ///     - hostname: The SFTP server hostname.
    ///     - port: The SFTP server port name.
    ///     - username: The user name to authenticate as.
    ///     - prvKeyPath: The path of file containing the private key to use.
    ///     - passphrase: The key passphrase to use - is no passphrase was set, pass a blank string.
    public init(hostname: String, port: Int, username: String,
         prvKeyPath: String, passphrase: String) {
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.prvKeyPath = prvKeyPath
        self.passphrase = passphrase
        
        self.prvKey = ""
        self.password = ""
        self.sshAgentSocketPath = ""
    }
    
    /// Create a new connection with public key based authentication data read from a string.
    /// - Parameters:
    ///     - hostname: The SFTP server hostname.
    ///     - port: The SFTP server port name.
    ///     - username: The user name to authenticate as.
    ///     - prvKey: The private key to use.
    ///     - passphrase: The key passphrase to use - is no passphrase was set, pass a blank string.
    public init(hostname: String, port: Int, username: String,
         prvKey: String, passphrase: String) {
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.prvKey = prvKey
        self.passphrase = passphrase
        
        self.prvKeyPath = ""
        self.password = ""
        self.sshAgentSocketPath = ""
    }
    
    /// Create a new connection with ssh-agent based auth
    /// - Parameters:
    ///     - hostname: The SFTP server hostname.
    ///     - port: The SFTP server port name.
    ///     - username: The user name to authenticate as.
    ///     - sshAgentSocketPath: Path to ssh-agent unix socket
    public init(hostname: String, port: Int, username: String, sshAgentSocketPath: String) {
        self.hostname = hostname
        self.port = port
        self.username = username
        self.sshAgentSocketPath = sshAgentSocketPath
        
        self.prvKey = ""
        self.passphrase = ""
        self.prvKeyPath = ""
        self.password = ""
    }
    
    deinit {
        disconnect()
        releaseIconv()
    }
    
    // MARK: - Connection, Authentication, Dicsonnection
    
    /// Determine the server connectivity state.
    public var connected: Bool {
        if session != nil {
            return ssh_is_connected(session) == 1
        }
        return false
    }
    
    /// Establish connection with the server.
    /// - Throws: NSError on connection error.
    public func connect() throws {
        try _connect()
    }
    
    /// Connect to the server.
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
        
        if self.sshAgentSocketPath != "" {
            if ssh_options_set(session, SSH_OPTIONS_IDENTITY_AGENT, self.sshAgentSocketPath) < 0 {
                defer {
                    ssh_free(session)
                    session = nil
                }
                throw error_ssh()
            }
        }
        
        var x: Int32 = 0
        if ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &x) < 0 {
            defer {
                ssh_free(session)
                session = nil
            }
            throw error_ssh()
        }
        
        let ciphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc"
        let compression = "none,zlib,zlib@openssh.com"
        if ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, ciphers) < 0 ||
            ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, ciphers) < 0 ||
            ssh_options_set(session, SSH_OPTIONS_COMPRESSION, compression) < 0 {
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
    
    /// Authentucate on the server. Prior to calling this function, the connection to the server.
    /// must be established.
    /// - Throws: NSError on error.
    public func authenticate() throws {
        
        if session == nil {
            throw error(code: .no_session)
        }
        
        try _authenticate()
        try _sftpSession()
    }
    
    /// Turns number representing an authentication methods (as returned by ssh_userauth_list())
    /// to a list with these methods names.
    ///  - Parameters:
    ///     - supported: Number returned by ssh_userauth_list().
    ///  - Returns: List of supported authentication methods names.
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
    
    /// Authenticates the user.
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
        
        if self.sshAgentSocketPath != "" {
            auth = ssh_userauth_agent(session, nil)
        } else if self.prvKeyPath != "" || self.prvKey != "" {
            
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
    
    /// Authenticate the user with using the public key method.
    func _authenticatePublicKey() throws -> Int32 {
        
        var auth: Int32
        var pk: ssh_key?
        
        // make pk based on a file of string
        if self.prvKeyPath != "" {  // from a file
            if FileManager.default.fileExists(atPath: self.prvKeyPath) == false {
                ssh_disconnect(session)
                ssh_free(session)
                session = nil
                throw error(code: .authentication_failed)
            } else {
                auth = ssh_pki_import_privkey_file(self.prvKeyPath, self.passphrase, nil, nil, &pk)
            }
        } else { // from memory
            auth = ssh_pki_import_privkey_base64(self.prvKey, self.passphrase, nil, nil, &pk)
        }
        
        // authenticate using pk
        if auth == 0 && pk != nil {
            auth = ssh_userauth_publickey(session, nil, pk)
            ssh_key_free(pk)
        } else {
            ssh_disconnect(session)
            ssh_free(session)
            session = nil
            throw error(code: .wrong_keyfile)
        }
        
        return auth
    }
    
    /// Authenticate the user with using the interactive method.
    func _authenticateInteractive() throws -> Int32 {
        
        var auth = ssh_userauth_kbdint(session, nil, nil)
        if auth == SSH_AUTH_INFO.rawValue {
            //let name = ssh_userauth_kbdint_getname(session)
            //let inst = ssh_userauth_kbdint_getinstruction(session)
            let nprompts = ssh_userauth_kbdint_getnprompts(session)
            if (nprompts == 1) {
                //var echo: Int8 = 1
                //let prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo)
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
    
    /// Create a new SFTP session.
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
    
    /// Disconnect.
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
    
    /// Return the connection info. The connection must be established but does not have to
    /// be authenticated.
    /// - Returns: Connection info.
    /// - Throws: NSError on error and also when the connection is not established.
    public func connectionInfo() throws -> MFTSftpConnectionInfo {
    
        if session == nil {
            throw error(code: .no_session)
        }
        
        let ret = MFTSftpConnectionInfo()
        
        if let sbanner = ssh_get_serverbanner(session) {
            ret.serverBanner = stringWith(buf: sbanner) ?? ""
        }
        if let ibanner = ssh_get_issue_banner(session) {
            ret.issueBanner = stringWith(buf: ibanner) ?? ""
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
        
        if let lim = sftp_limits(sftp_session) {
            ret.maxOpenHandles = lim.pointee.max_open_handles
            ret.maxPacketLenght = lim.pointee.max_packet_length
            ret.maxReadLenght = lim.pointee.max_read_length
            ret.maxWriteLenght = lim.pointee.max_write_length
            sftp_limits_free(lim)
        }
        
        return ret;
    }
    
    // MARK: - Directory listing and items info
    
    /// Return the content of the given directory on the SFTP server. ".", ".." and items with names that cannot
    /// be converted using the current encoding are skipped.
    /// - Parameters:
    ///     - path: Remote directory path.
    ///     - maxItems: Limit for the number of items to returns,  0 = no limit.
    /// - Returns: List of MFTSftpItem representing itemes on the given directory.
    /// - Throws: NSError on error.
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
            defer {sftp_attributes_free(file)}
            
            if file.pointee.name == nil
                || String(cString: file.pointee.name) == "."
                || String(cString: file.pointee.name) == ".." {
                continue
            }
            
            if let fname = stringWith(buf: file.pointee.name) {
            
                var ownerS = ""
                var groupS = ""
                
                if let owner = file.pointee.owner {
                    ownerS = stringWith(buf: owner) ?? ""
                }
                if let group = file.pointee.group {
                    groupS = stringWith(buf: group) ?? ""
                }
                
                let item = MFTSftpItem(name: fname,
                                    size: file.pointee.size,
                                    uid: file.pointee.uid,
                                    gid: file.pointee.gid,
                                    owner: ownerS,
                                    group: groupS,
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
        }
        
        if limitReached == false && sftp_dir_eof(dir) == 0 {
            throw error_sftp()
        }

        if sftp_closedir(dir) != 0 {
            throw error_sftp()
        }
        
        return ret
    }
    
    /// Returns information for the remote item at the given path.
    /// - Parameters:
    ///     - atPath: The remote item path.
    /// - Returns: Temote item info.
    /// - Throws: NSError on error (also when there is no item at the given path).
    public func infoForFile(atPath: String) throws -> MFTSftpItem {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let path: String
        if atPath == "." {
            if let p = sftp_canonicalize_path(sftp_session, ".") {
                defer {ssh_string_free_char(p)}
                path = stringWith(buf: p) ?? ""
            } else {
                path = ""
            }
        } else {
            path = atPath
        }
        
        if path == "" {
            throw error(code: .file_not_found)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let file = sftp_stat(sftp_session, pathC) {
            defer {sftp_attributes_free(file)}
            
            var fullPath = path
            if fullPath.hasPrefix("/") == false {
                fullPath = try canonicalPath(forPath: fullPath)
            }
            
            if fullPath.hasPrefix("/") == false {
                // this should not happen
                throw error(code: .file_not_found)
            }
            
            var ownerS = ""
            var groupS = ""
            
            if let owner = file.pointee.owner {
                ownerS = stringWith(buf: owner) ?? ""
            }
            if let group = file.pointee.group {
                groupS = stringWith(buf: group) ?? ""
            }
            
            let item = MFTSftpItem(name: fullPath,
                                size: file.pointee.size,
                                uid: file.pointee.uid,
                                gid: file.pointee.gid,
                                owner: ownerS,
                                group: groupS,
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

    /// Return canonical (absolute) path for the given path
    /// - Parameters:
    ///     - path: the path to canonicalize.
    /// - Returns: The canonical path.
    /// - Throws: NSError on error.
    public func canonicalPath(forPath path:String) throws -> String {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let file = sftp_canonicalize_path(sftp_session, pathC) {
            defer {ssh_string_free_char(file)}
            if let n = stringWith(buf: file) {
                return n
            } else {
                throw error(code: .file_not_found)
            }
        } else {
            throw error_sftp()
        }
    }
    
    /// Resolve the target of the given symbolic link.
    /// - Parameters:
    ///     - path: Symbolic link path.
    /// - Returns: The link target path.
    /// - Throws: NSError on error, also when the path does not point to a symbolic link.
    public func effectiveTarget(forPath path:String) throws -> String {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let file = sftp_readlink(sftp_session, pathC) {
            defer {ssh_string_free_char(file)}
            if let n = stringWith(buf: file) {
                return n
            } else {
                throw error(code: .file_not_found)
            }
        } else {
            throw error_sftp()
        }
    }
    
    // MARK: - Creating and removing
    
    /// Create a new directory at the given path.
    /// - Parameters:
    ///     - path: The path of the folder to create.
    /// - Throws: NSError on error.
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
    
    /// Create a new symbolic link.
    /// - Parameters:
    ///     - path: The path of the symbolic link to create.
    ///     - destPath: The target of the symbolic link to create.
    /// - Throws: NSError on error.
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

    /// Remote the directory at the given path.
    /// - Parameters:
    ///     - path: The path to remove.
    /// - Throws: NSError on error.
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
    
    /// Remote the file or the symbolic link at the given path.
    /// - Parameters:
    ///     - path: The path to remove.
    /// - Throws: NSError on error.
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
    
    /// Download the content of the file at the given path to the output stream.
    /// - Parameters:
    ///     - path: The path of the file to download.
    ///     - outputStream: The output strem to use for storing donwloaded content - if the stream is closed, it will be opened.
    ///     - pos: Starting position in the source file to download - if >0, the outputStram must be create for appending.
    ///     - progress: Progress report callback - its two arguments are used to download bytes counter (including skipped bytes)
    ///     and the size of the file to download. The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
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
            
            var rqCount = defRqCount
            var chunkSize: UInt64 = defChunkSize
            if let lim = sftp_limits(sftp_session) {
                chunkSize = min(102400, lim.pointee.max_read_length)
                if lim.pointee.max_open_handles > 0 {
                    rqCount = min(rqCount, Int(lim.pointee.max_open_handles))
                }
                sftp_limits_free(lim)
            }
            
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(chunkSize))
            defer { buf.deallocate() }
            var q = [UnsafeMutablePointer<sftp_aio?>]()
            defer {
                while q.count > 0 {
                    let aioh = q.removeFirst()
                    sftp_aio_free(aioh.pointee)
                }
            }
            
            var totalReadCount = pos
            var totalWriteCount = pos
            for _ in 0..<rqCount {
                let aioh = UnsafeMutablePointer<sftp_aio?>.allocate(capacity: 1)
                let readCount = sftp_aio_begin_read(file, Int(chunkSize), aioh)
                if readCount < 0 {
                    throw error_sftp()
                }
                q.append(aioh)
            }
            
            while q.count > 0 {
                let aioh = q.removeFirst()
                let readCount = sftp_aio_wait_read(aioh, buf, Int(chunkSize))
                if readCount > 0 {
                    totalReadCount += UInt64(readCount)
                    // write to a local file
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
                    totalWriteCount += UInt64(readCount)
                    if progress != nil && progress!(totalWriteCount, fileInfo.size) == false {
                        throw errorCancelled()
                    }
                } else if readCount < 0 {
                    throw error_sftp()
                } else {
                    // EOF
                    break
                }
                
                if totalReadCount < fileInfo.size {
                    let readCount = sftp_aio_begin_read(file, Int(chunkSize), aioh)
                    if readCount > 0 {
                        q.append(aioh)
                    } else if readCount < 0 {
                        throw error_sftp()
                    }
                }
            }
        } else {
            throw error_sftp()
        }
    }

    // MARK: - Upload
    
    /// Upload the content of the given input stream to the remove file at path.
    /// - Parameters:
    ///     - inputStream: The source of data to upload.
    ///     - path: The path of the file to upload to.
    ///     - append: Should the upload append to the file.
    ///     - progress: Progress report callback - its argument represents uploaded bytes counter (including skipped bytes).
    ///     The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
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
        
        
        var flags : Int32 = O_CREAT|O_WRONLY;
        if append == false {
            flags |= O_TRUNC
        }
        if let file = sftp_open(sftp_session, pathC, flags, 0o644) {
            defer {sftp_close(file)}
            
            var progressStartsFrom: UInt64 = 0
            if append {
                do {
                    let fileInfo = try infoForFile(atPath: path)
                    inputStream.setProperty(fileInfo.size, forKey: .fileCurrentOffsetKey)
                    if inputStream.hasBytesAvailable == false {
                        throw error(code: .local_read_error)
                    }
                    sftp_seek64(file, fileInfo.size)
                    progressStartsFrom = fileInfo.size
                } catch let error as NSError {
                    if error.domain == "sftp" && error.code == SSH_FX_NO_SUCH_FILE {
                        // file not found may happen when it is not there for some servers even after sftp_open was called
                        // here is basically mean that we have nothing to append to - no need to error exit
                    } else {
                        throw error
                    }
                }
            }
            
            try _write(stream: inputStream, toFileHandle: file, progressStartsFrom: progressStartsFrom,
                       progress: progress)
            
        } else {
            throw error_sftp()
        }
    }
    
    /// Write the content of the given input stream to the SFTP file handle.
    func _write(stream inputStream: InputStream, toFileHandle file:sftp_file, progressStartsFrom: UInt64,
                progress:((UInt64) -> (Bool))?) throws {
          
        var chunkSize: UInt64 = defChunkSize
        var rqCount = defRqCount
        if let lim = sftp_limits(sftp_session) {
            chunkSize = lim.pointee.max_write_length
            if lim.pointee.max_open_handles > 0 {
                rqCount = min(rqCount, Int(lim.pointee.max_open_handles))
            }
            sftp_limits_free(lim)
        }
        
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(chunkSize))
        defer { buf.deallocate() }
        var q = [UnsafeMutablePointer<sftp_aio?>]()
        defer {
            while q.count > 0 {
                let aioh = q.removeFirst()
                sftp_aio_free(aioh.pointee)
            }
        }
        
        for _ in 0..<rqCount {
            let readCount = inputStream.read(buf, maxLength: Int(chunkSize))
            if readCount > 0 {
                let aioh = UnsafeMutablePointer<sftp_aio?>.allocate(capacity: 1)
                if sftp_aio_begin_write(file, buf, min(Int(chunkSize), readCount) , aioh) < 0 {
                    throw error_sftp()
                }
                q.append(aioh)
            } else if readCount < 0 {
                throw error(code: .local_read_error)
            } else {
                break
            }
        }
        var totalWriteCount = progressStartsFrom
        while q.count > 0 {
            let aioh = q.removeFirst()
            let writeCount = sftp_aio_wait_write(aioh)
            if writeCount > 0 {
                totalWriteCount += UInt64(writeCount)
                if progress != nil && progress!(totalWriteCount) == false {
                    throw errorCancelled()
                }
            } else {
                throw error_sftp()
            }
            let readCount = inputStream.read(buf, maxLength: Int(chunkSize))
            if readCount > 0 {
                let chunkSize = sftp_aio_begin_write(file, buf, min(Int(chunkSize), readCount), aioh)
                if chunkSize < 0 {
                    throw error_sftp()
                }
                q.append(aioh)
            } else if readCount < 0 {
                throw error(code: .local_read_error)
            }
        }
    }
    
    // MARK: - Copy
    
    /// Copy the item to a new path of the SFTP server.
    /// - Parameters:
    ///     - fromPath: Source path (on the server).
    ///     - toPath: Destination path (on the server).
    ///     - progress: Progress report callback - its two arguments are used to copied bytes counter
    ///     and the size of the file to copy. The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
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
                
                var chunkSize: UInt64 = defChunkSize
                if let lim = sftp_limits(sftp_session) {
                    chunkSize = min(lim.pointee.max_read_length, lim.pointee.max_write_length)
                    sftp_limits_free(lim)
                }
                
                var totalReadCount: UInt64 = 0
                var totalWriteCount: UInt64 = 0
                
                let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(chunkSize))
                defer { buf.deallocate() }
                
                var readCount = sftp_read(fromFile, buf, Int(chunkSize))
                
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
                    
                    readCount = sftp_read(fromFile, buf, Int(chunkSize))
                }
                
                if readCount < 0 {
                    throw error_sftp()
                }
            }
        }
    }
    
    // MARK: - Move/rename
    
    /// Move the item to a new path on the SFTP server. The operation is performed on the server without
    /// downloading/uploading the file data.
    /// - Parameters:
    ///     - atPath: The current path of the item to move.
    ///     - toPath: The the path of the item.
    /// - Throws: NSError on error.
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
    
    /// Set modification and access time of the remote item.
    /// - Parameters:
    ///     - mtime: Modification time to set.
    ///     - atime: Access time to set.
    ///     - path: The item path.
    /// - Throws: NSError on error.
    public func set(modificationTime mtime:Date?, accessTime atime:Date?, forPath path:String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        var fileAttrs = sftp_attributes_struct()
        fileAttrs.flags = UInt32(SSH_FILEXFER_ATTR_ACMODTIME)
        if mtime != nil {
            fileAttrs.mtime = UInt32(mtime!.timeIntervalSince1970)
        } else {
            fileAttrs.mtime = 0
        }
        if (atime != nil) {
            fileAttrs.atime = UInt32(atime!.timeIntervalSince1970)
        } else {
            fileAttrs.atime = 0
        }
        if sftp_setstat(sftp_session, pathC, &fileAttrs) < 0 {
            throw error_sftp()
        }
    }
    
    /// Set permissions for the given remote item.
    /// - Parameters:
    ///     - permissions: POSIX permissions to set.
    ///     - path: The item path to set permissions.
    /// - Throws: NSError on error.
    public func set(permissions:UInt32, forPath path:String) throws {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        var fileAttrs = sftp_attributes_struct()
        fileAttrs.permissions = permissions
        fileAttrs.flags = UInt32(SSH_FILEXFER_ATTR_PERMISSIONS)
        if sftp_setstat(sftp_session, pathC, &fileAttrs) < 0 {
            throw error_sftp()
        }
    }

    // MARK: - Filesystem info
    
    /// Returns file system info.
    /// - Parameters:
    ///     - path: The path of the item to return file system info for.
    /// - Returns: File system info for the file system on which the given item resides.
    /// - Throws: NSError on error.
    public func filesystemStats(forPath path: String) throws -> MFTFilesystemStats {
        
        if sftp_session == nil {
            throw error(code: .no_session)
        }
        
        let pathC = cString(for: path)
        defer {pathC.deallocate()}
        
        if let stat = sftp_statvfs(sftp_session, pathC) {
            defer {sftp_statvfs_free(stat)}
            let size = UInt64(stat.pointee.f_frsize * stat.pointee.f_blocks)
            let freeSpace = UInt64(stat.pointee.f_bavail * stat.pointee.f_frsize)
            return MFTFilesystemStats(size: size, freeSpace: freeSpace)
            
        } else {
            throw error_sftp()
        }
    }
    
    // MARK: - Knownhost
    
    /// Check is connected host is known based on hashes in the given file.
    /// - Parameters:
    ///     - path: The path of file with the known hosts hashes.
    /// - Returns: One of MFTKnownHostStatus representing the status. Note, that this function does not throw an exception,
    /// but instead in case when there is no connection it returns .NO_SESSION.
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
    
    /// Add the hash of the connected host to the given file.
    /// - Parameters:
    ///     - path: The path of the file with known hosts hashes.
    /// - Throws: NSError on error.
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
    
    /// Returns the human readable fingerprint hash for the current connection.
    /// - Returns: The fingerprint hash.
    /// - Throws: NSError on error.
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
    
    /// Upload the file at the given file to the remote file.
    /// - Parameters:
    ///     - path: The  source (local) file path.
    ///     - toFileAtPath: The destination (remote) file path.
    ///     - progress: Progress report callback - its argument represents uploaded bytes counter.
    ///     The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
    public func uploadFile(atPath path: String, toFileAtPath:String, progress:((UInt64) -> (Bool))?) throws {
        if FileManager.default.isReadableFile(atPath: path) == false {
            throw error(code: .local_file_not_readable)
        }
        let istream = InputStream(fileAtPath: path)
        if istream == nil {
            throw error(code: .local_open_error_for_reading)
        }
        try write(stream: istream!, toFileAtPath: toFileAtPath, append: false, progress: progress)
    }
    
    /// Resume uploads of the file at the given file to the remote file.
    /// - Parameters:
    ///     - path: The  source (local) file path.
    ///     - toFileAtPath: The destination (remote) file path.
    ///     - progress: Progress report callback - its argument represents uploaded bytes counter (including skipped bytes).
    ///     The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
    public func resumeUploadFile(atPath path: String, toFileAtPath:String, progress:((UInt64) -> (Bool))?) throws {
        if FileManager.default.isReadableFile(atPath: path) == false {
            throw error(code: .local_file_not_readable)
        }
        let istream = InputStream(fileAtPath: path)
        if istream == nil {
            throw error(code: .local_open_error_for_reading)
        }
        try write(stream: istream!, toFileAtPath: toFileAtPath, append: true, progress: progress)
    }
    
    /// Download the file at the given path to the local file.
    /// - Parameters:
    ///     - path: The source (remote) file path.
    ///     - toFileAtPath: The destination (local) file path.
    ///     - progress: Progress report callback - its two arguments are used to download bytes counter
    ///     and the size of the file to download. The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
    public func downloadFile(atPath path: String, toFileAtPath:String,
                             progress:((UInt64, UInt64) -> (Bool))?) throws {
        if FileManager.default.isWritableFile(atPath: toFileAtPath) == false {
            throw error(code: .local_file_not_writable)
        }
        let ostream = OutputStream(toFileAtPath: toFileAtPath, append: false)
        if ostream == nil {
            throw error(code: .local_open_error_for_writing)
        }
        try contents(atPath: path, toStream: ostream!, fromPosition: 0, progress: progress)
    }
    
    /// Resume download of the file at the given path to the local file.
    /// - Parameters:
    ///     - path: The source (remote) file path.
    ///     - toFileAtPath: The destination (local) file path.
    ///     - progress: Progress report callback - its two arguments are used to download bytes counter (including skipped bytes)
    ///     and the size of the file to download. The return value false can be used to abort the operation.
    /// - Throws: NSError on error.
    public func resumeDownloadFile(atPath path: String, toFileAtPath:String,
                             progress:((UInt64, UInt64) -> (Bool))?) throws {
        if FileManager.default.isWritableFile(atPath: toFileAtPath) == false {
            throw error(code: .local_file_not_writable)
        }
        var pos: UInt64 = 0
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: toFileAtPath)
            pos = (attrs as NSDictionary).fileSize()
        } catch {}
        let ostream = OutputStream(toFileAtPath: toFileAtPath, append: pos>0)
        if ostream == nil {
            throw error(code: .local_open_error_for_writing)
        }
        try contents(atPath: path, toStream: ostream!, fromPosition: pos, progress: progress)
    }

    // MARK: - Errors
    
    /// Create and resurn SSH error based on the current session state.
    func error_ssh() -> NSError {
        let msg = String(cString: ssh_get_error(UnsafeMutableRawPointer(session!))!)
        let code = ssh_get_error_code(UnsafeMutableRawPointer(session!))
        return NSError(domain: "ssh", code: Int(code), userInfo: [NSLocalizedDescriptionKey: msg])
    }
    
    /// Create and resurn SFTP error based on the current SFTP session state.
    func error_sftp() -> NSError {
        let msg = String(cString: ssh_get_error(UnsafeMutableRawPointer(session!))!)
        var code = sftp_get_error(sftp_session)
        if code == 0 {
            // fall-back to ssh errors
            code = ssh_get_error_code(UnsafeMutableRawPointer(session!))
            // let's not mix error ranges
            if code != 0 {
                code += 1000
            }
            return NSError(domain: "sftp", code: Int(code), userInfo: [NSLocalizedDescriptionKey: msg])
        } else {
            let msg1 = message(forSftpError: code)
            return NSError(domain: "sftp", code: Int(code), userInfo: [NSLocalizedDescriptionKey: msg + ": " + msg1])
        }
    }
    
    /// Create and return MFT error with the given code and its default message.
    func error(code: MFTErrorCode) -> NSError {
        let msg = message(forError: code)
        return error(code: code, msg: msg)
    }
    
    /// Create and return MFT error with the given code and message.
    func error(code: MFTErrorCode, msg: String) -> NSError {
        return NSError(domain: "mft", code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: msg])
    }
    
    /// Create and return MFT error for canceled operations.
    func errorCancelled() -> NSError {
        return error(code: .canceled)
    }
    
    /// Get a message for the given MFT error.
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
            
        case .local_file_not_writable:
            return NSLocalizedString("You don't have permission to write the file", comment: "")
            
        case .wrong_keyfile:
            return NSLocalizedString("Wrong keyfile format or wrong passphrase", comment: "")
            
        case .file_not_found:
            return NSLocalizedString("Item not found", comment: "")
            
        case .canceled:
            return NSLocalizedString("Canceled", comment: "")
            
        default:
            return NSLocalizedString("Error", comment: "")
        }
    }
    
    /// Get a message for the given SFTP error.
    func message(forSftpError error: Int32) -> String {
        
        func NSLocalizedString(_ key: String, comment: String) -> String {
            return Bundle(for: MFTSftpConnection.self).localizedString(forKey: key, value: "", table: nil)
        }
        
        switch error {
            
        case SSH_FX_OK:
            return NSLocalizedString("No error", comment: "")
            
        case SSH_FX_EOF:
            return NSLocalizedString("No error", comment: "")
            
        case SSH_FX_NO_SUCH_FILE:
            return NSLocalizedString("File doesn't exist", comment: "")
            
        case SSH_FX_PERMISSION_DENIED:
            return NSLocalizedString("Permission denied ", comment: "")
            
        case SSH_FX_FAILURE:
            return NSLocalizedString("Generic failure", comment: "")
            
        case SSH_FX_BAD_MESSAGE:
            return NSLocalizedString("Garbage received from server", comment: "")
            
        case SSH_FX_NO_CONNECTION:
            return NSLocalizedString("No connection has been set up", comment: "")
            
        case SSH_FX_CONNECTION_LOST:
            return NSLocalizedString("There was a connection, but we lost it", comment: "")
            
        case SSH_FX_OP_UNSUPPORTED:
            return NSLocalizedString("Operation not supported by the server", comment: "")
            
        case SSH_FX_INVALID_HANDLE:
            return NSLocalizedString("Invalid file handle", comment: "")
            
        case SSH_FX_NO_SUCH_PATH:
            return NSLocalizedString("No such file or directory path exists", comment: "")
            
        case SSH_FX_FILE_ALREADY_EXISTS:
            return NSLocalizedString("An attempt to create an already existing file or directory has been made", comment: "")
            
        case SSH_FX_WRITE_PROTECT:
            return NSLocalizedString("We are trying to write on a write-protected filesystem", comment: "")
            
        case SSH_FX_NO_MEDIA:
            return NSLocalizedString("No media in remote drive", comment: "")
            
        default:
            return NSLocalizedString("Unknown error", comment: "")
        }
    }
    
    // MARK: - Encoding conversion
    
    var convNil: iconv_t = iconv_t.init(bitPattern: -1)!
    var convToUtf8: iconv_t = iconv_t.init(bitPattern: -1)!
    var convFromUtf8: iconv_t = iconv_t.init(bitPattern: -1)!
    var _encoding: String?
    
    /// SFTP server characters encoding.
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
    
    /// Clean-up iconv handlers.
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
    
    /// Create and return C-style string with the selected encoding (in the 'encoding' property) for the given string.
    /// - Parameters:
    ///     s: String to convert.
    /// - Returns: Converted string in the buffer. The buffer must be released by the called by calling its .deallocate() method.
    func cString(for s: String) -> UnsafePointer<CChar> {
        let buf = UnsafeMutablePointer<CChar>.allocate(capacity: s.convBufSize())
        return (s as NSString).toBuf(buf, bufLenght: s.convBufSize(), iconvFromUtf8: convFromUtf8)
    }
    
    /// Create a new string from the C-style string with the selected encoding (in the 'encoding' property).
    /// - Parameters:
    ///     - buf: C-style string (encoded).
    /// - Returns: Converted string or nil if conversion fails (it happens when the string is not encoded with 'encoding').
    func stringWith(buf: UnsafePointer<CChar>) -> String? {
        return NSString(buf: buf, iconvToUtf8: convToUtf8) as String?
    }
}
