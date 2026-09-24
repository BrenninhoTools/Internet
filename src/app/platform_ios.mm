#import <UIKit/UIKit.h>

#include "platform.hpp"

namespace internet {
namespace platform {

namespace {

UIViewController* topController() {
    UIWindow* window = nil;
    for (UIScene* scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow* candidate in ((UIWindowScene*)scene).windows) {
            if (candidate.isKeyWindow) {
                window = candidate;
                break;
            }
        }
        if (window != nil) break;
    }
    UIViewController* controller = window.rootViewController;
    while (controller.presentedViewController != nil) controller = controller.presentedViewController;
    return controller;
}

}

bool shareText(const std::string& text) {
    NSString* string = [NSString stringWithUTF8String:text.c_str()];
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController* controller = topController();
        if (controller == nil) return;
        UIActivityViewController* sheet = [[UIActivityViewController alloc] initWithActivityItems:@[ string ]
                                                                            applicationActivities:nil];
        sheet.popoverPresentationController.sourceView = controller.view;
        sheet.popoverPresentationController.sourceRect =
            CGRectMake(CGRectGetMidX(controller.view.bounds), CGRectGetMidY(controller.view.bounds), 0, 0);
        [controller presentViewController:sheet animated:YES completion:nil];
    });
    return true;
}

void haptic(int) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIImpactFeedbackGenerator* generator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
        [generator impactOccurred];
    });
}

std::string takeLaunchLink() { return std::string(); }

void setHosting(bool, const std::string&) {}

}
}
