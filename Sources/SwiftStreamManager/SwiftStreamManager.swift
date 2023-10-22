//
//  SwiftStreamManager.swift
//  SwiftStreamManager
//
//  Created by Iain McLaren on 12/7/2023.
//

import Foundation
import SwiftUI
import SwiftWebSocketManager
import SwiftKeyExchange

/// StreamManagerError error.
public enum StreamManagerError: Error {
    case decryptAndDecodeFailure
}

///  Function to create a new KeyExchangeStore.  Alternatively, create a similar function using a custom KeyExchangeStore().
public var KeyExchange_Curve25519_SHA256_HKDF_AESGCM = { return try! KeyExchange_Curve25519_SHA256_HKDF_AESGCM_Store("") }
public var KeyExchange_Curve25519_SHA384_HKDF_AESGCM = { return try! KeyExchange_Curve25519_SHA384_HKDF_AESGCM_Store("") }
public var KeyExchange_Curve25519_SHA512_HKDF_AESGCM = { return try! KeyExchange_Curve25519_SHA512_HKDF_AESGCM_Store("") }

public class StreamManager: ObservableObject {
        
    // Reset variables
    public var keyExchangeStoreFunction: () -> KeyExchangeStore
    public var baseURL: URL?
    public var port: Int?
    public var urlRequest: URLRequest?

    // Optional binary arguments
    public var pidArgumentKey: String?
    public var urlArgumentKey: String?
    public var portArgumentKey: String?
    public var bearerTokenArgumentKey: String?
    
    // WebSocketManager
    @Published var wm: WebSocketManager = WebSocketManager()
    @Published var stream: WebSocketStream = WebSocketStream()

    // KeyExchangeStore
    public var kes: KeyExchangeStore = KeyExchangeStore()
    public var timestamp = KeyExchangeCurrentTimestamp() // Int64 current time since 1970 in milliseconds.
        
    // decryptAndDecodeJSON failure count
    var decryptFailureCount = 0
    
    // Has the StreamManager been closed
    private var isDone: Bool = false
    
    /// Cancel the StreamManager
    public func cancel() {
        self.wm.cancel()
    }

    /// Terminate the currently running binary.
    /// If the processManager withRetry option is set to true, the binary will restart.
    public func reset() {
        self.wm.terminateCurrentTask()
    }
    
    /// Initiate the StreamManager
    /// - Parameters:
    ///   - keyExchangeStoreFunction: Function that creates a new KeyExchangeStore.
    ///   - baseURL: Base URL for the websocket server (without the path).
    ///   - port: The wesbocket connection port.
    ///   - urlRequest: The wesbocket connection URLRequest.
    public init(
        _ keyExchangeStoreFunction: @escaping () -> KeyExchangeStore,
        baseURL: URL? = nil,
        port: Int? = nil,
        urlRequest: URLRequest? = nil
    ) {
        self.keyExchangeStoreFunction = keyExchangeStoreFunction
        self.baseURL = baseURL
        self.port = port
        self.urlRequest = urlRequest
    }
    
    /// Add the pid of this executable as an argument to the binary in the form "-key=PID".
    /// The binary can then use this PID to terminate when the calling parent terminates.
    /// - Parameter key: The argument.
    public func addPIDAsArgument(_ key: String) {
        self.pidArgumentKey = key
    }

    /// Add the WebSocketManagerr base url as an argument to the binary in the form "-key=ws://127.0.0.1:8573".
    /// - Parameter key: The argument.
    public func addURLAsArgument(_ key: String) {
        self.urlArgumentKey = key
    }

    /// Add the WebSocketManager port as an argument to the binary in the form "-key=8573".
    /// - Parameter key: The argument.
    public func addPortAsArgument(_ key: String) {
        self.portArgumentKey = key
    }

    /// Add the bearer token as an argument to the binary in the form "-key=token".
    /// - Parameter key: The argument.
    public func addBearerTokenAsArgument(_ key: String) {
        self.bearerTokenArgumentKey = key
    }
    
    /// Decrypts (i.e. performs the opposite of the Encrypt function) the ciphertext using the provided kdfNonce, ciphertext, aeadNonce, and additionalData.  All of this information is included in KeyExchangeAEADStore structs.
    ///
    ///  Then decode the decrypted data into the provided type.
    ///
    /// - Parameters:
    ///   - message: The URLSessionWebSocketTask.Message
    ///   - kes: The KeyExchangeStore used to decrypt the data.
    ///   - auth: Function that validates whether the KeyExchangeStore additionalData is valid.
    /// - Throws: KeyExchangeError.invalidFormat
    /// - Returns: The decoded JSON.
    public func decryptAndDecodeJSON<T: Decodable>(
        message: URLSessionWebSocketTask.Message,
        auth: @escaping (String) throws -> Bool = { _ in return true }
    ) throws -> T {
        guard let result: T = try KeyExchangeDecryptAndDecodeJSON(
            message: message,
            kes: self.kes,
            auth: auth
        ) else {
            decryptFailureCount+=1
            if decryptFailureCount > 10 {
                print("reset - decryptAndDecodeJSON has failed 10 times in a row")
                decryptFailureCount = 0
                self.reset()
            }
            throw StreamManagerError.decryptAndDecodeFailure
        }
        return result
    }
    
    /// Subscibe to a websocket server.
    /// - Parameters:
    ///   - messages: Send each URLSessionWebSocketTask.Message to this function.
    ///   - errors: Send all Error? messages to this function.
    public func subscribe(
        _ stream: WebSocketStream,
        messages:@escaping (URLSessionWebSocketTask.Message) -> Void = { _ in },
        errors:@escaping (Error) -> Void = { _ in }
    ) {
        self.wm.subscribe(
            stream: stream,
            messages: messages,
            errors: errors
        )
    }
    
    /// Start a binary and connect to a websocket server (generally the bundled binary will be the websocket server).
    /// - Parameters:
    ///   - streamPath: URL path for the base stream.
    ///   - urlRequest: URLRequest for the base sream.
    ///   - binName: The name of the bundled binary to run.
    ///   - withRetry: If true, restarts the binary if it exits.
    ///   - withPEMWatcher: Watch binary output for a public key String in the Privacy-Enhanced Mail (PEM), and update the KeyExchangeStore external public key using this PEM.
    ///   - pingTimeLimit: Time before the function calls pingTimeLimit - messages received will act as a pong() as will calling self.pong().
    ///   - pingTimeout: Triggers when pingTimeLimit is reached without any pongs.  Never triggered if pingTimeLimit <= 0.
    ///   - standardOutput: Send the binary standard output to the provided function.
    ///   - taskExitNotification: Send an Error? to the provided function each time the binary exits.
    ///   - messages: Send each URLSessionWebSocketTask.Message to the provided function.
    ///   - onConnected: Triggers when the first stream is connected.
    ///   - errors: Send all websocket Error? messages to this function.
    public func subscribeWithBinary(
        streamPath: String? = nil,
        urlRequest: URLRequest? = nil,
        binName: String,
        withRetry: Bool = true,
        withPEMWatcher: Bool = false,
        pingTimeLimit: TimeInterval = 65.0,
        pingTimeout: @escaping () -> Void = {},
        standardOutput: @escaping (String) -> Void  = { _ in },
        taskExitNotification: @escaping (Error?) -> Void  = { _ in },
        messages: @escaping (URLSessionWebSocketTask.Message) -> Void = { _ in },
        onConnected: @escaping () -> Void = {},
        errors:@escaping (Error) -> Void = { _ in }
    ) {
        subscribeWithBinary(
            streamPath: streamPath,
            urlRequest: urlRequest,
            binURL: Bundle.main.url(forResource: binName, withExtension: nil)!,
            withRetry: withRetry,
            withPEMWatcher: withPEMWatcher,
            pingTimeLimit: pingTimeLimit,
            pingTimeout: pingTimeout,
            standardOutput: standardOutput,
            taskExitNotification: taskExitNotification,
            messages: messages,
            onConnected: onConnected,
            errors: errors
        )
    }
    
    /// Create a WebSocketStream
    /// - Parameters:
    ///   - streamPath: URL path for the  stream.
    ///   - urlRequest: URLRequest for the  sream.
    /// - Returns: The WebSocketStream
    public func stream(
        streamPath: String? = nil,
        urlRequest: URLRequest? = nil
    ) throws -> WebSocketStream {
        return try self.wm.connect(
            path: streamPath,
            urlRequest: urlRequest,
            bearerToken: self.kes.LocalPublicKey()
        )
    }
    
    /// Start a binary and connect to a websocket server (generally the bundled binary will be the websocket server).
    /// - Parameters:
    ///   - streamPath: URL path for the base stream.
    ///   - urlRequest: URLRequest for the base sream.
    ///   - binURL: The URL of the binary to run.
    ///   - withRetry: If true, restarts the binary if it exits.
    ///   - withPEMWatcher: Watch binary output for a public key String in the Privacy-Enhanced Mail (PEM), and update the KeyExchangeStore external public key using this PEM.
    ///   - pingTimeLimit: Time before the function calls pingTimeLimit - messages received will act as a pong() and will calling self.pong().
    ///   - pingTimeout: Triggered when pingTimeLimit is reached without any pongs.  Never triggered if pingTimeLimit <= 0.
    ///   - standardOutput: Send the binary standard output to the provided function.
    ///   - taskExitNotification: Send an Error? to the provided function each time the binary exits.
    ///   - messages: Send each URLSessionWebSocketTask.Message to the provided function.
    ///   - onConnected: Triggers when the first stream is connected.
    ///   - errors: Send all websocket Error? messages to this function.
    public func subscribeWithBinary(
        streamPath: String? = nil,
        urlRequest: URLRequest? = nil,
        binURL: URL,
        withRetry: Bool = true,
        withPEMWatcher: Bool = false,
        pingTimeLimit: TimeInterval = 65.0,
        pingTimeout: @escaping () -> Void = {},
        standardOutput: @escaping (String) -> Void  = { _ in },
        taskExitNotification: @escaping (Error?) -> Void  = { _ in },
        messages: @escaping (URLSessionWebSocketTask.Message) -> Void = { _ in },
        onConnected:@escaping () -> Void = {},
        errors:@escaping (Error) -> Void = { _ in }
    ) {
        // Initiate KeyExchangeStore and WebSocketManager
        self.kes = self.keyExchangeStoreFunction()
        self.wm = WebSocketManager(
            //url: self.url,
            baseURL: self.baseURL,
            port: self.port
            //bearerToken: self.kes.LocalPublicKey()
        )
        
        self.stream = try! self.wm.connect(
            path: streamPath,
            urlRequest: urlRequest,
            bearerToken: self.kes.LocalPublicKey()
        )
        
        Task(priority: .medium) {
            
            var isStarted = false

            // Add binary argumants
            if self.pidArgumentKey != nil {
                self.wm.processManager.addPIDAsArgument(pidArgumentKey!)
            }
            
            if self.urlArgumentKey != nil {
                self.wm.processManager.addArgument(urlArgumentKey!, value: self.baseURL!)
            }
             
            if self.portArgumentKey != nil {
                //self.wm.processManager.addArgument(portArgumentKey!, value: self.wm.url!.port!)
                self.wm.processManager.addArgument(portArgumentKey!, value: self.port!)
            }
            if self.bearerTokenArgumentKey != nil {
                self.wm.processManager.addArgument(bearerTokenArgumentKey!, value: self.kes.LocalPublicKey())
            }
            
            // run binary
            await self.wm.subscribeWithBinary(
                stream: self.stream,
                binURL: binURL,
                withRetry: withRetry,
                pingTimeLimit: pingTimeLimit,
                pingTimeout: {
                    pingTimeout()
                    print("ping timeout - reset")
                    self.reset()
                },
                standardOutput: { output in
                    standardOutput(output)
                    
                    
                    
                    if withPEMWatcher {
                        guard let publicKey = PEMSearchString(output) else {
                            return
                        }
                        do {
                            try self.kes.setExternalPublicKey(publicKey)
                        } catch {
                            print("pem search parse error - reset")
                            self.reset()
                        }
                    }
                },
                taskExitNotification: { error in
                    taskExitNotification(error)
                    print("task exited")
                    if error != nil {
                        print(error!)
                    } 
                    //self.reset()
                },
                messages: { message in
                    self.wm.pong()
                    
                    if !isStarted {
                        isStarted = true
                        onConnected()
                    }
                    messages(message)
                },
                errors: { err in
                    errors(err)
                }
            )
        }
    }
    
    /// Authenticate using an additionalData String timestamp (tracking the current time as an Int64 since 1970 in milliseconds).
    /// - Parameter additionalData: The additionalData string
    /// - Returns: Authentication success or failure Bool.
    public func authTimestamp(_ additionalData: String) -> Bool {
    
        // Only process new messages
        guard let t = KeyExchangeTimestamp(additionalData) else {
            return false
        }
        if t <= self.timestamp {
            return false
        }
        
        // Allow up to 10 milliseconds of jitter
        let delta = KeyExchangeCurrentTimestamp()-t
        if delta < 0 || delta > 10 {
            return false
        }
        self.timestamp = t
        return true
    }
    
    /// Publish a WebSocketTypeIDAndData struct as JSON to the  WebSocketStream.
    /// - Parameters:
    ///   - stream: The WebSocketStream.
    ///   - type: String.
    ///   - id: String.
    ///   - data: String.
    ///   - additionalData: The additionalData used to authenticate.  Defaults to KeyExchangeCurrentTimestampData().
    public func publish(
        _ stream: WebSocketStream,
        type: String,
        id: String,
        data: String,
        additionalData: Data = KeyExchangeCurrentTimestampData()
    ) {
        do {
            self.wm.publish(
                stream,
                try self.kes.encodeJSONAndEncrypt(
                    type: type,
                    id: id,
                    data: data,
                    additionalData: additionalData
                ),
                errors: { error in
                    if error != nil {
                        print(error!)
                    }
                }
            )
        } catch {
            print(error)
        }
    }
        
    /// Publish a generic Encodable item to the WebSocketStream.
    /// - Parameters:
    ///   - stream: The WebSocketStream.
    ///   - value: The Encodable item to send to the .websocket server.
    ///   - additionalData: The additionalData used to authenticate.  Defaults to KeyExchangeCurrentTimestampData().
    public func publish<T>(
        _ stream: WebSocketStream,
        _ value: T,
        additionalData: Data = KeyExchangeCurrentTimestampData()
    ) where T : Encodable {
        do {
            self.wm.publish(
                stream,
                try self.kes.encodeJSONAndEncrypt(
                    value,
                    additionalData: additionalData
                ),
                errors: { error in
                    if error != nil {
                        print(error!)
                    }
                }
            )
        } catch {
            print(error)
        }
    }
}
