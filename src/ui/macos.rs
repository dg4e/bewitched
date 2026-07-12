//! macOS Apple-menu integration.
//!
//! winit builds the standard application menu and wires its "About bewitched"
//! item to `orderFrontStandardAboutPanel:`, which pops the stock system about
//! panel. We want it to show the *same* animated about as the program's Help ▸
//! "about bewitched" instead. So at startup we find that menu item and redirect
//! its action to a tiny Objective-C target object; clicking it sets a flag the
//! egui app polls each frame (see `App::update`) to open `about_window`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{declare_class, msg_send_id, mutability, sel, ClassType, DeclaredClass};
use objc2_app_kit::NSApplication;
use objc2_foundation::MainThreadMarker;

/// Set when the native About item is clicked; the UI thread polls and clears it.
static ABOUT_REQUESTED: AtomicBool = AtomicBool::new(false);
/// A clone of the egui context, so the menu callback can wake an idle UI.
static CTX: Mutex<Option<egui::Context>> = Mutex::new(None);

/// Returns `true` once per native About-menu click. Polled each frame.
pub fn take_about_requested() -> bool {
    ABOUT_REQUESTED.swap(false, Ordering::Relaxed)
}

declare_class!(
    struct AboutTarget;

    // SAFETY:
    // - The superclass NSObject has no subclassing requirements.
    // - Interior mutability is the safe default and we hold no `&mut self`.
    // - AboutTarget does not implement `Drop`.
    unsafe impl ClassType for AboutTarget {
        type Super = NSObject;
        type Mutability = mutability::InteriorMutable;
        const NAME: &'static str = "BewitchedAboutTarget";
    }

    impl DeclaredClass for AboutTarget {}

    unsafe impl AboutTarget {
        #[method(showAboutBewitched:)]
        fn show_about(&self, _sender: Option<&AnyObject>) {
            ABOUT_REQUESTED.store(true, Ordering::Relaxed);
            if let Some(ctx) = CTX.lock().unwrap().as_ref() {
                ctx.request_repaint();
            }
        }
    }
);

impl AboutTarget {
    fn new() -> Retained<Self> {
        unsafe { msg_send_id![Self::alloc(), init] }
    }
}

/// Redirect the Apple-menu "About bewitched" item to the in-app about window.
///
/// Must run on the main thread (it does, from `App::new`). A no-op if the menu
/// isn't there yet or has no standard-about item — we simply leave the default.
pub fn install(ctx: &egui::Context) {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    *CTX.lock().unwrap() = Some(ctx.clone());

    let app = NSApplication::sharedApplication(mtm);
    // SAFETY: all run on the main thread; these are plain AppKit accessors.
    unsafe {
        let Some(menubar) = app.mainMenu() else {
            return;
        };
        // The application menu is the submenu of the first menubar item.
        let Some(app_item) = menubar.itemAtIndex(0) else {
            return;
        };
        let Some(app_menu) = app_item.submenu() else {
            return;
        };

        let std_about = sel!(orderFrontStandardAboutPanel:);
        for i in 0..app_menu.numberOfItems() {
            let Some(item) = app_menu.itemAtIndex(i) else {
                continue;
            };
            if item.action() == Some(std_about) {
                let target = AboutTarget::new();
                item.setTarget(Some(&target));
                item.setAction(Some(sel!(showAboutBewitched:)));
                // NSMenuItem does not retain its target, so keep ours alive for
                // the lifetime of the process.
                std::mem::forget(target);
                break;
            }
        }
    }
}
