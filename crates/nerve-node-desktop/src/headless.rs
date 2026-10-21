//! A window without a screen, drawn by Slint's software renderer: for the
//! tests that drive the app against a node, and for the screenshots of its
//! pages (tests/shots.rs). There is no event loop; [`Exec::Inline`]
//! (crate::app) runs the commands at once instead. The window keeps the
//! sizes the app asks of a real one, so a test sees whether it fits a screen.

use std::cell::Cell;
use std::rc::{Rc, Weak};

use slint::platform::software_renderer::{RepaintBufferType, SoftwareRenderer};
use slint::platform::{
    LayoutConstraints, Platform, PlatformError, Renderer, WindowAdapter, WindowEvent,
    WindowProperties,
};
use slint::{LogicalSize, PhysicalSize, Rgba8Pixel, SharedPixelBuffer, WindowSize};

/// Slint's minimal software window, which also keeps what the app's
/// layout asks of the window.
struct Window {
    window: slint::Window,
    renderer: SoftwareRenderer,
    size: Cell<PhysicalSize>,
    constraints: Cell<LayoutConstraints>,
}

impl WindowAdapter for Window {
    fn window(&self) -> &slint::Window {
        &self.window
    }

    fn renderer(&self) -> &dyn Renderer {
        &self.renderer
    }

    fn size(&self) -> PhysicalSize {
        self.size.get()
    }

    fn set_size(&self, size: WindowSize) {
        let scale = self.window.scale_factor();
        self.size.set(size.to_physical(scale));
        self.window.dispatch_event(WindowEvent::Resized {
            size: size.to_logical(scale),
        });
    }

    // Asked again whenever what it read changes.
    fn update_window_properties(&self, properties: WindowProperties<'_>) {
        self.constraints.set(properties.layout_constraints());
    }
}

struct Headless {
    window: Rc<Window>,
}

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }
}

/// The screen of this thread's windows.
pub struct Screen {
    window: Rc<Window>,
}

impl Screen {
    /// Puts the headless platform in place; once per process, before the
    /// first window.
    pub fn install(width: u32, height: u32, scale: f32) -> Result<Screen, String> {
        let window = Rc::new_cyclic(|w: &Weak<Window>| Window {
            window: slint::Window::new(w.clone()),
            renderer: SoftwareRenderer::new_with_repaint_buffer_type(RepaintBufferType::NewBuffer),
            size: Cell::new(PhysicalSize::default()),
            constraints: Cell::new(LayoutConstraints::default()),
        });
        slint::platform::set_platform(Box::new(Headless {
            window: window.clone(),
        }))
        .map_err(|e| format!("the headless platform: {e}"))?;
        window
            .window
            .dispatch_event(WindowEvent::ScaleFactorChanged {
                scale_factor: scale,
            });
        window.window.set_size(PhysicalSize::new(width, height));
        Ok(Screen { window })
    }

    /// Makes the window `width` by `height` pixels: a long page in one
    /// picture.
    pub fn resize(&self, width: u32, height: u32) {
        self.window
            .window
            .set_size(PhysicalSize::new(width, height));
    }

    /// What the window's content asks of the window, in logical pixels:
    /// the smallest size, which a window manager keeps the window from going
    /// below, and the size it opens with.
    pub fn wants(&self) -> (LogicalSize, LogicalSize) {
        slint::platform::update_timers_and_animations();
        let c = self.window.constraints.get();
        (c.min.unwrap_or_default(), c.preferred)
    }

    /// Draws what the window shows now.
    pub fn draw(&self) -> SharedPixelBuffer<Rgba8Pixel> {
        slint::platform::update_timers_and_animations();
        let size = self.window.size.get();
        let mut pixels = SharedPixelBuffer::<Rgba8Pixel>::new(size.width, size.height);
        let mut buffer = vec![
            slint::platform::software_renderer::PremultipliedRgbaColor::default();
            (size.width * size.height) as usize
        ];
        self.window
            .renderer
            .render(&mut buffer, size.width as usize);
        for (out, p) in pixels.make_mut_slice().iter_mut().zip(buffer) {
            // Premultiplied to straight alpha; the window is opaque.
            *out = Rgba8Pixel {
                r: p.red,
                g: p.green,
                b: p.blue,
                a: 255,
            };
        }
        pixels
    }
}
