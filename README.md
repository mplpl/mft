# mft
Swift SFTP Client Framework

The mft is a framework that makes it easy to access SFTP services from Swift as well as Objective-C. 
It uses modern backend - libssh and OpenSSL - with all the security related features and algorithmes (like aes-gcm or chacha20-poly) and can be embedded in macOS (both x86 and arm64) and iOS/iPadOS apps.

## Capabilities

The mft framework has the following capabilities.

### Connectivity
* Using the following ciphers: chacha20-poly, aes-gcm, aes-ctr, aes-cbc, 3des-cbc 
* Using the following MAC hashing: hmac-sha2-etm, hmac-sha1-etm, hmac-sha2, hmac-sha1
* Using zlib compression
* Support for password authentication
* Support for public-key authentication
* Simple support for interactive authentication (with only a password prompt)
* Support for ed25519, ecdsa, rsa-sha2, ssh-rsa and ssh-dss public key algorithms
* Support for SFTP servers with non-UTF-8 charset

### Supported SFTP Operations
* Browsing directories
* Recognizing directories, files, and symbolic links
* Creating directories
* Creating symbolic links
* Removing directories
* Removing files
* Removing symbolic links
* Downloading files
* Downloading files from the given position (resume download)
* Uploading files
* Uploading files with append to existing (resume upload)
* Reporting progress of downloading/uploading
* Copying items within the same SFTP server
* Moving items within the same SFTP server
* Renaming items
* Setting modification and access timestamps for items
* Setting POSIX permissions for items
* Retrieving file system stats (total size and utilization)

### Supported environments
* macOS x86_64, 
* macOS arm64, 
* iOS arm64, 
* iOS Simulator arm64, 
* iOS Simulator x86_64

### Supported programming languages
* Swift
* Objective-C

## Bundled components

The mft framework bundles the compiled versions of the following open source libraries:
* libssh 0.11.0
* openssl 3.3.1

## Building mft framework

The mft should be built into an xcframework, that can easily be embedded in Xcode projects. To do that:

1) Make sure you have Xcode installed and your Apple Developer account configured in Xcode preferences
2) Clone the mft source code from git
```
git clone https://github.com/mplpl/mft
```
3) Open the mft project in Xcode, go to settings of the "mft" target, and verify that there are no errors on "Signing & Capabilities". If they are, check the configuration of your developer account. Repeat the check for the "mft ios" target

4) Close Xcode and open Terminal, go to mft folder, and call:
```
./build.sh
```
This starts a build process. The result will be located in a new folder created at the same level as mft folder, with the name "mft CURRENT_DATE_AND_TIME" (for example mft 2022-09-21 11-50-57). In that folder, you can find mft.xcframework folder, that is the outcome of the build.

## Using mft framework

1) Create a new Xcode project, for example, macOS command line tool in Swift (it can also be Objective-C or iOS/iPadOS)

2) In your new project go to its target configuration, and on the "General" tab click the "+" icon under "Framework and Libraries". Then select "Add Other...", "Add File..." and then select mft.xcframework folder created during a build

3) Now you can write your code. Use "import mft" to enable the framework access in your source file. Here you have a simple example of how mft can be used in Swift

```
import Foundation
import mft

do {
    var sftp: MFTSftpConnection!
    sftp = MFTSftpConnection(hostname: "123.123.123.123",
                                 port: 22,
                                 username: "your_user_name",
                                 password: "your_secret_password)
    
    // Connect and authenticate
    try sftp.connect()
    try sftp.authenticate()
    
    // List remote directory items
    let items = try sftp.contentsOfDirectory(atPath: "/tmp", maxItems: 0)
    for item in items {
        NSLog("%@", item.filename)
    }
    
    // Upload a file
    let localFileToUpload = "/bin/cat"
    let uploadRemotePath = "upload_test"
    let inStream = InputStream(fileAtPath: localFileToUpload)
    let srcAttrs = try FileManager.default.attributesOfItem(atPath: localFileToUpload) as NSDictionary
    
    try sftp.write(stream: inStream!, toFileAtPath: uploadRemotePath, append: false) { uploaded in
        NSLog("Upload progress: %d / %d", uploaded, srcAttrs.fileSize())
        return true
    }
    
    // Download a file
    let remoteFileToDownload = "upload_test"
    let localDownloadTarget = "/tmp/download_test"
    let outStream = OutputStream(toFileAtPath: localDownloadTarget, append: false)
    
    try sftp.contents(atPath: remoteFileToDownload, toStream: outStream!, fromPosition: 0) {
        downloaded, total in
        
        NSLog("Download progress: %d / %d", downloaded, total)
        return true
    }
    
    // Remove remote file
    try sftp.removeFile(atPath: uploadRemotePath);
    
    // Disconnect
    sftp.disconnect()
    
} catch {
    print(error.localizedDescription)
}
```


