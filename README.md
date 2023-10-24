# SwiftStreamManager

Run a golang binary embedded in a native macOS SwiftUI app.

The golang binary and SwiftUI app communicate via encrypted websocket messages.

Works well on macOS 13 (Ventura) and later.  Earlier versions of macOS appear to have a memory leak in URLSessionWebSocketTask which requires an app restart about every 15 minutes.

## Setup

Create a new macOS Swift Xcode project:
- File -> Add Packages ... -> https://github.com/calmdocs/SwiftStreamManager
- Select the checkbox at Target -> Signing & Capabilities -> App Sandbox -> Network -> Incoming connections (Server).
- Select the checkbox at Target -> Signing & Capabilities -> App Sandbox -> Network -> Incoming connections (Client).

## Example

### Create our go binaries (for amd64 and arm64)

Run the following commands:
- git clone https://github.com/calmdocs/SwiftStreamManager
- cd SwiftStreamManager/pkg/gobinary
- GOOS=darwin GOARCH=amd64 go build -o gobinary-darwin-amd64 && GOOS=darwin GOARCH=arm64 go build -o gobinary-darwin-arm64

Drag the gobinary-darwin-amd64 and gobinary-darwin-arm64 files that we just built into our new macOS Swift Xcode project.

### In our new Swift Xcode project, replace ContentView.swift with the following code:

```
import SwiftUI

import SwiftStreamManager
import SwiftWebSocketManager
import SwiftProcessManager

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

struct ContentView: View {
    @ObservedObject var itemsStore: ItemsStore = ItemsStore()
     
    var body: some View {
        List {
            HStack {
                Button(action: {
                    itemsStore.sm.publish(
                        itemsStore.sendStream!,
                        type: "addItem",
                        id: "",
                        data: ""
                    )
                }, label: {
                    Image(systemName: "plus")
                })
                Spacer()
            }
            ForEach(itemsStore.items) { item in
                HStack{
                    Text("\(item.name) (\(item.status))")
                    Spacer()
                    Button(action: {
                        itemsStore.sm.publish(
                            itemsStore.sendStream!,
                            type: "deleteItem",
                            id: String(item.id),
                            data: ""
                        )
                    }, label: {
                        Image(systemName: "trash")
                    })
                }
            }
        }
    }
}

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
                    auth: self.sm.authTimestamp  // Use the current time since 1970 in milliseconds as the default key exchange auth key.
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
## Security

We have been as conservative as possible when creating this library.  See the security details available on the [calmdocs/SwiftKeyExchange package page](https://github.com/calmdocs/SwiftKeyExchange). Please note that you use this library and the code in this repo at your own risk, and we accept no liability in relation to its use.
