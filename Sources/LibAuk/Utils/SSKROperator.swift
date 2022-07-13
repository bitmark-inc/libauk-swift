//
//  SSKROperator.swift
//  
//
//  Created by Thuyên Trương on 04/07/2022.
//

import SSKR

public class SSKROperator {

    public static func generate(data: Data,
                                groupThreshold: Int,
                                numberOfShardsInGroup: UInt8,
                                shardsCombinationThreshold: UInt8,
                                randomGenerator: @escaping ((Int) -> Data) = generateRandomGenerator()) throws -> [[SSKRShare]] {

        let groups = [SSKRGroupDescriptor(threshold: shardsCombinationThreshold, count: numberOfShardsInGroup)]
        return try SSKRGenerate(groupThreshold: groupThreshold,
                                groups: groups,
                                secret: data,
                                randomGenerator: randomGenerator)

    }

    public static func combine(shares: [SSKRShare]) throws -> Data {
        return try SSKRCombine(shares: shares)
    }

    public static func generateRandomGenerator() -> (Int) -> Data {
        { len in
            var randomBytes = [UInt8](repeating: 0, count: len)
            _ = SecRandomCopyBytes(kSecRandomDefault, len, &randomBytes)
            return Data(randomBytes)
        }
    }

}
