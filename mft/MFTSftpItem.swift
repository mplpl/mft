//
//  SftpItem.swift
//  mft
//
//  Created by Marcin Labenski on 28/01/2022.
//  Copyright © 2022 Marcin Labenski. All rights reserved.
//

import Foundation

/// This class represents a single SFTP items - a directory, file or symbilic link.
@objcMembers public class MFTSftpItem: NSObject {
    
    public let filename: String
    public let size: UInt64
    public let uid: UInt32
    public let gid: UInt32
    public let owner: String
    public let group: String
    public let permissions: UInt32
    
    public let atime: Date
    public let atimeNanos: UInt32
    public let mtime: Date
    public let mtimeNanos: UInt32
    public let createTime: Date
    public let createTimeNanos: UInt32
    
    public let isDirectory: Bool
    public let isSymlink: Bool
    public let isSpecial: Bool
    
    init(name: String, size: UInt64, uid: UInt32, gid: UInt32, owner: String, group: String,
         permissions: UInt32, atime: UInt32, atimeNanos: UInt32, mtime: UInt32, mtimeNanos: UInt32,
         createTime:UInt64, createTimeNanos: UInt32, isDir: Bool, isSymlink: Bool, isSpecial: Bool) {
        
        self.filename = name
        self.size = size
        self.uid = uid
        self.gid = gid
        self.owner = owner
        self.group = group
        self.permissions = permissions
        self.atime = Date(timeIntervalSince1970: TimeInterval(atime))
        self.atimeNanos = atimeNanos
        self.mtime = Date(timeIntervalSince1970: TimeInterval(mtime))
        self.mtimeNanos = mtimeNanos
        self.createTime = Date(timeIntervalSince1970: TimeInterval(createTime))
        self.createTimeNanos = createTimeNanos
        self.isDirectory = isDir
        self.isSpecial = isSpecial
        self.isSymlink = isSymlink
    }
}
