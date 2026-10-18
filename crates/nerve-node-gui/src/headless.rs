//! A window without a screen, drawn by Slint's software renderer: for the
//! tests that drive the app against a node, and for the screenshots of its
//! pages (tests/shots.rs). There is no event loop; [`Exec::Inline`]
//! (crate::app) runs the commands at once instead.

use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, PlatformError, WindowAdapter, WindowEvent};
use slint::{PhysicalSize, Rgba8Pixel, SharedPixelBuffer};

struct Headless {
    window: Rc<MinimalSoftwareWindow>,
}

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }
}

/// The screen of this thread's windows.
pub struct Screen {
    window: Rc<MinimalSoftwareWindow>,
}

impl Screen {
    /// Puts the headless platform in place; once per process, before the
    /// first window.
    pub fn install(width: u32, height: u32, scale: f32) -> Result<Screen, String> {
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(Headless {
            window: window.clone(),
        }))
        .map_err(|e| format!("the headless platform: {e}"))?;
        window.dispatch_event(WindowEvent::ScaleFactorChanged {
            scale_factor: scale,
        });
        window.set_size(PhysicalSize::new(width, height));
        Ok(Screen { window })
    }

    /// Draws what the window shows now.
    pub fn draw(&self) -> SharedPixelBuffer<Rgba8Pixel> {
        slint::platform::update_timers_and_animations();
        let size = self.window.size();
        let mut pixels = SharedPixelBuffer::<Rgba8Pixel>::new(size.width, size.height);
        self.window.request_redraw();
        self.window.draw_if_needed(|renderer| {
            let mut buffer = vec![
                slint::platform::software_renderer::PremultipliedRgbaColor::default();
                (size.width * size.height) as usize
            ];
            renderer.render(&mut buffer, size.width as usize);
            for (out, p) in pixels.make_mut_slice().iter_mut().zip(buffer) {
                // Premultiplied to straight alpha; the window is opaque.
                *out = Rgba8Pixel {
                    r: p.red,
                    g: p.green,
                    b: p.blue,
                    a: 255,
                };
            }
        });
        pixels
    }
}
