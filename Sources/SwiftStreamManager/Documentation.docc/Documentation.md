# ``SwiftStreamManager``

Run a golang binary embedded in a native macOS SwiftUI app.  

The golang binary and SwiftUI app communicate with each other via websockets.

## Setup

- Create a new macOS Swift Xcode project:
    - File -> Add Packages ... -> https://github.com/calmdocs/SwiftStreamManager
    - Select the checkbox at Target -> Signing & Capabilities -> App Sandbox -> Network -> Incoming connections (Server).
    - Select the checkbox at Target -> Signing & Capabilities -> App Sandbox -> Network -> Incoming connections (Client).
    - Drag our Apple Silicon (e.g. "gobinary-darwin-arm64") and arm64 (e.g. "gobinary-darwin-amd64") golang binary files into the Swift Xcode project.
- Build and run the Swift app.

## Example

### Create two go binaries (one for older amd64 Macs, and one for new Apple Silicon Macs)

- Copy the gobinary.go example file from this respository into a new folder called "gobinary".
- Run the following commands in the new gobinary folder to build our golang binaries:
    - go mod init github.com/myusername/gobinary
    - go mod tidy
    - GOOS=darwin GOARCH=amd64 go build -o gobinary-darwin-amd64 && GOOS=darwin GOARCH=arm64 go build -o gobinary-darwin-arm64

Drag the gobinary-darwin-amd64 and gobinary-darwin-arm64 files that we just built into the macOS Swift Xcode project.

### In our new Swift Xcode project, create a struct to store our items

```
public struct CustomStorageItem: Codable, Identifiable {
    public var id: Int64
    
    let error: String?
    let name: String
    let status: String
    let progress: Double

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case error = "Error"
        case name = "Name"
        case status = "Status"
        case progress = "Progress"
    }
}
```
### In our Swift Xcode project, create an ItemsStore

```
import SwiftStreamManager
import SwiftProcessManager    // For the SystemArchitecture() function.

// Items store
class ItemsStore: ObservableObject {

    private let binName = SystemArchitecture() == "arm64" ? "gobinary-darwin-arm64" : "gobinary-darwin-amd64"

    @Published var items: [CustomStorageItem] = [CustomStorageItem]()
    
    // StreamManager
    @Published var sm: StreamManager
    @Published var sendStream: WebSocketStream?
  
    init() {
      
        // Initialise StreamManager
        self.sm = StreamManager(
            KeyExchange_Curve25519_SHA256_HKDF_AESGCM,
            baseURL: URL(string: "ws://127.0.0.1")!,
            port: Int.random(in: 8001..<9000)
        )
        self.sm.addPIDAsArgument("pid")
        self.sm.addBearerTokenAsArgument("token")
        self.sm.addPortAsArgument("port")
        
        // Start binary and subscribe to a websocket stream
        self.sm.subscribeWithBinary(
            streamPath: "/ws/0",
            binName: self.binName,
            withPEMWatcher: true,
            standardOutput: { result in
                print(result)
            },
            messages: { message in

                // Decrypt and decode
                guard let newItems: [CustomStorageItem] = try? self.sm.decryptAndDecodeJSON(
                    message: message,
                    auth: self.sm.authTimestamp  // Use the current time since 1970 in milliseconds as the default auth key.
                ) else {
                    return
                }

                // Update items
                DispatchQueue.main.async {
                    self.items.replaceInPlace(items: newItems)
                }                
            },
            onConnected: {
                
                // Create a second (sending) stream subscribed to a different path
                DispatchQueue.main.async {
                    self.sendStream = try! self.sm.stream(streamPath: "/ws/1")
                    self.sm.subscribe(self.sendStream!,
                        //messages: { message in
                        //    print(message)
                        //},
                        errors: { err in
                            print(err)
                        }
                    )
                }
            }
        )
    }
}
        
```
### In the Swift Xcode project, update the ContentView to list and edit our items

```
struct ContentView: View {
    @ObservedObject var itemsStore: ItemsStore
     
    var body: some View {
        Button(action: {
            itemsStore.sendStream.publish(itemsStore.sendStream!, type: "addItem", id: "", data: "")
        }, label: {
            Image(systemName: "plus")
        })
        List {
            ForEach(itemsStore.items) { item in
                HStack{
                    Text(item.name)     
                    Spacer()
                    Button(action: {
                            ip.sendStream.publish(
                                itemsStore.sendStream!,
                                type: "deleteItem",
                                id: String(item.id),
                                data: ""
                            )
                        }, label: {
                            Image(systemName: "trash")
                        }
                    )
                }
            }
        }
    }
}
```
## How this works and security considerations

We have been as conservative as possible when creating this library.  See the security discussion below and the security details available on the [calmdocs/SwiftKeyExchange package page](https://github.com/calmdocs/SwiftKeyExchange). Please note that you use this library and the code in this repo at your own risk, and we accept no liability in relation to its use.

### The issue
[calmdocs/SwiftStreamManager](https://github.com/calmdocs/SwiftStreamManager) connects from a SwiftUI app to a local websoket server.  The golang binary runs the websocket server.

Traditionally, in order to connect from a SwiftUI app to a websocket server on the same macOS device, our options were:
- do not encrypt;
- connect to a local websocket server using a self-signed certificate not issued by a certificate authority (CA), but do not validate on the client side that we are using this self-signed certificate; or
- embed a self-signed certificate in both the SwiftUI app and the websocket server.

The first is insecure, the second allows for person-in-the-middle attacks (and so is insecure), and the third is very difficult to implement in practice.

### SwiftStreamManager's approach
In order to implement Diffie–Hellman key exchange ([DHKE](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)), the server and the client both need to create public keys.  The server needs to send its public key to the client, and the client needs to send its public key to the server.

SwiftStreamManager does the following:
- The SwiftUI app creates its public key, then starts a binary (using Process()) and adds the public key as an argument to this binary.
- The binary creates a public key and sends this public key to stdOut in [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) format to be read by the SwiftUI app.
- The SwiftUI app and the binary now have both public keys.  The binary runs a websocket server, the SwiftUI app connects to this server, and each message is be excrypted using Diffie–Hellman key exchange ([DHKE](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)).

### Security and threat model considerations
We have been as conservative as possible with our approach here, including by only using the the [Apple CryptoKit Framework](https://developer.apple.com/documentation/cryptokit/) and equivalent golang libraries for the client (see [calmdocs/keyexchange](https://github.com/calmdocs/keyexchange)).  

Also, please note the following:
- If the local macOS system is compromised, or your threat model includes the local user as an attacker, the local user could create a malicious SwiftUI app that runs and provides a public key to the local binary.  This could be mitigated (for example) by both the SwiftUI app and the binary separately authenticating (and/or sharing public keys) using an external server.
- If the local websocket port is already in-use by another app or process (or blocked due to a DDOS attacck), then the websocket connection will be blocked.  The example code above runs SwiftManager on a random open port between 8000 and 9000 to minimise the risk that this will occur accidentially.  Running on a random port also allows multiple different local apps to use this library on the same macOS machine.
- The current version of [calmdocs/SwiftKeyExchange](https://github.com/calmdocs/SwiftKeyExchange) used in the example above does not allow an attacker to send multiple copies of valid messages (given that we use a timestamp as the additionalData variable), but does allow individual messages to be blocked by an attacker (or lost/dropped).  If potentially missing messages is an issue for you, add a count variable to your CustomStorageItem struct (or equivalent) for each of the messages that you send and receive.  Also see our comments in [calmdocs/SwiftKeyExchange](https://github.com/calmdocs/SwiftKeyExchange) regarding using [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) instead, given that using [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) would not allow any messages to be missed or dropped. 

Please notify us of any security issues by creating a github issue.  Please propose how you would like to securely communicate with us (via email or other communication method).  Please do not post the potential security issue on github.
