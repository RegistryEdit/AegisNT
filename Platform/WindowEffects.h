#pragma once

#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>

#include <algorithm>
#include <windows.h>

namespace Platform {

inline void ApplyWindowOpacity(GLFWwindow *Window, double Opacity) {
  if (!Window)
    return;

  HWND Hwnd = glfwGetWin32Window(Window);
  if (!Hwnd)
    return;

  LONG ExStyle = GetWindowLongW(Hwnd, GWL_EXSTYLE);
  if ((ExStyle & WS_EX_LAYERED) == 0) {
    SetWindowLongW(Hwnd, GWL_EXSTYLE, ExStyle | WS_EX_LAYERED);
  }

  const BYTE Alpha =
      static_cast<BYTE>(std::clamp(Opacity, 0.35, 1.0) * 255.0 + 0.5);
  SetLayeredWindowAttributes(Hwnd, 0, Alpha, LWA_ALPHA);
}

} // namespace Platform
