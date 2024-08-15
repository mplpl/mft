//
//  String+md5.swift
//  mftTests
//
//  Created by Marcin Labenski on 15/08/2024.
//  Copyright © 2024 Marcin Labenski. All rights reserved.
//

import Cocoa

extension String {
    func md5() -> String {
        let pipe = Pipe()
        let task = Process()
        task.launchPath = "/sbin/md5"
        task.arguments = ["-q", self]
        task.standardOutput = pipe;
        task.launch()
        let fh = pipe.fileHandleForReading
        let taskData = fh.readDataToEndOfFile()
        let dataString = String(bytes: taskData, encoding: .utf8)
        if let results = dataString?.components(separatedBy: "\n") {
            if results.count > 0 {
                return results[1]
            }
        }
        return ""
    }
}
