#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <assert.h>
#include <dlfcn.h>
static NSDictionary *capabilities(void) { return @{@"ReceiverModelName":@"MacTest"}; }
#include "../src/mac/airdrop/AQOutgoing.inc"
static NSData *native_body;
static NSData *original_body(id client,SEL selector,NSInteger format) {
    (void)client; (void)selector; (void)format; return native_body;
}
int main(void) { @autoreleasepool {
    original_ask_body=original_body;
    NSObject *client=[NSObject new];
    NSDictionary *offer=@{@"SenderEmailHash":@"legacy-contact-hash",
        @"SenderID":@"123456789abc",@"SenderComputerName":@"Sending Mac",
        @"Files":@[@{@"FileName":@"example.txt",@"FileIsDirectory":@NO}],
        @"UnknownField":@"preserve"};
    NSString *identifier=nil;
    for(NSNumber *encoding in @[@(NSPropertyListBinaryFormat_v1_0),@(NSPropertyListXMLFormat_v1_0)]) {
        NSPropertyListFormat format=[encoding integerValue], actual=0;
        native_body=[NSPropertyListSerialization dataWithPropertyList:offer format:format options:0 error:NULL];
        NSData *body=ask_body(client,@selector(askBodyDataInFormat:),format);
        NSDictionary *result=[NSPropertyListSerialization propertyListWithData:body options:0 format:&actual error:NULL];
        assert(actual==format && !result[@"SenderEmailHash"]);
        for(NSString *key in @[@"SenderID",@"SenderComputerName",@"Files",@"UnknownField"])
            assert([result[key] isEqual:offer[key]]);
        assert([result[@"SenderModelName"] isEqual:@"MacTest"]);
        assert([result[@"ConvertMediaFormats"] isEqual:@NO]);
        assert([result[@"TransferType"] isEqual:@{@"files":@{}}]);
        NSString *next=result[@"TransferID"][@"id"];
        assert(next.length && (!identifier || [identifier isEqual:next])); identifier=next;
        NSDictionary *unchanged=[NSPropertyListSerialization propertyListWithData:native_body options:0 format:NULL error:NULL];
        assert([unchanged isEqual:offer]);
        // Applying the adaptation again to an anonymous offer is harmless.
        native_body=body;
        NSDictionary *again=[NSPropertyListSerialization propertyListWithData:ask_body(client,@selector(askBodyDataInFormat:),format) options:0 format:NULL error:NULL];
        assert([again isEqual:result]);
    }
    native_body=[@"not a property list" dataUsingEncoding:NSUTF8StringEncoding];
    assert(ask_body(client,@selector(askBodyDataInFormat:),NSPropertyListBinaryFormat_v1_0)==native_body);
    puts("PASS: modern offers omit legacy identity claims, preserve native file metadata and stable transfer IDs");
    return 0;
} }
