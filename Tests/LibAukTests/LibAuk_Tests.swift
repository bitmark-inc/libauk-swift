 import XCTest
 import Combine
 @testable import LibAuk

 final class LibAuk_Tests: XCTestCase {

     private var cancelBag: Set<AnyCancellable>!

     override func setUpWithError() throws {
         cancelBag = []
         LibAuk.create(keyChainGroup: "com.bitmark.autonomy")
     }

     override func tearDownWithError() throws {
         cancelBag.removeAll()
     }

     func testCreateAutonomyAccountVault() throws {
         XCTAssertEqual(LibAuk.shared.keyChainGroup, "com.bitmark.autonomy")
     }

     func testCalculateEthFirstAddressSuccessfully() throws {
         let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
         let passphrase = "feralfile"
         let receivedExpectation = expectation(description: "all values received")
         LibAuk.shared.calculateEthFirstAddress(words: words.components(separatedBy: " "), passphrase: passphrase)
             .sink(receiveCompletion: { completion in
                 switch completion {
                 case .finished:
                     receivedExpectation.fulfill()
                 case .failure(let error):
                     XCTFail("calculateEthFirstAddress failed \(error)")
                 }

             }, receiveValue: { ethAddress in
                 XCTAssertEqual(ethAddress, "0x459389605dF56EA4BBB0F11F1b6D68928C73384A")
             })
             .store(in: &cancelBag)

         waitForExpectations(timeout: 1, handler: nil)
     }

 }
