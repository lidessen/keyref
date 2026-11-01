// keyref 的视觉语言：冷调编辑排版。
//
// 一句话：整页近白（浅色）或近黑（深色），一条发丝线分层，标题大而紧，
// 数据一律等宽。琥珀只有一个用途——在小面积上点一下，像荧光笔标记，
// 提醒「这是信号」。除了状态色（成功 / 警告 / 危险），整页没有别的颜色，
// 也没有渐变、光晕、阴影和圆角泡泡。
//
// 深浅两套是同一套逻辑（不是两种风格）：所有自适应色走 UIColor 的动态
// provider。macOS 分支固定浅色——包在 macOS 上只做编译与测试。
import SwiftUI

#if os(iOS)
import UIKit
#endif

enum KeyrefTheme {
    // MARK: signal colors

    /// 唯一的强调色：琥珀，只作小面积信号（一粒方点、一个图标）。
    static let accent = adaptive(light: 0xB26A08, dark: 0xE8A33F)

    /// 系统控件的 accent：跟着前景色走。编辑排版不要彩色控件——链接、
    /// Tab 选中、工具栏文字都是近黑（浅色）/ 近白（深色）。
    static let tint = adaptive(light: 0x0A0A0A, dark: 0xF5F5F3)

    /// 前景色：正文与「反色块」共用。主按钮是它的实心块。
    static let foreground = adaptive(light: 0x0A0A0A, dark: 0xF5F5F3)

    static let success = adaptive(light: 0x1B7A3C, dark: 0x63D68C)
    static let warning = adaptive(light: 0x9A5B08, dark: 0xE7B04A)
    static let danger = adaptive(light: 0xBC2626, dark: 0xF08A8A)
    static let info = adaptive(light: 0x3D6E9E, dark: 0x93B8DC)

    // MARK: surfaces

    /// 页面底色。列表、详情、入口时刻用的是同一块底——不另起「保险库门」
    /// 那套深色皮肤，否则一个 App 会有两种身份。
    static let background = adaptive(light: 0xFAFAF9, dark: 0x0B0B0C)

    /// 需要一块「比页面更实」的面时用（sheet、输入框底）。
    static let surface = adaptive(light: 0xFFFFFF, dark: 0x151517)

    /// 发丝线：唯一的分层手段。
    static let hairline = adaptive(light: 0xE4E4E0, dark: 0x262629)

    static let muted = adaptive(light: 0x71716D, dark: 0x8C8C88)

    /// 明文层：与页面底色相反的一块实面——「秘密」在整页里是唯一的暗块
    /// （浅色下）或唯一的亮块（深色下），一眼能找到。
    static let slab = adaptive(light: 0x111113, dark: 0xF2F2EF)
    static let onSlab = adaptive(light: 0xF2F2EF, dark: 0x111113)

    // MARK: helpers

    static func adaptive(light: UInt32, dark: UInt32) -> Color {
        #if os(iOS)
        return Color(uiColor: UIColor { traits in
            UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light)
        })
        #else
        return Color(hex: light)
        #endif
    }
}

// MARK: - hex

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: alpha
        )
    }
}

#if os(iOS)
private extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(
            red: CGFloat((rgb >> 16) & 0xFF) / 255,
            green: CGFloat((rgb >> 8) & 0xFF) / 255,
            blue: CGFloat(rgb & 0xFF) / 255,
            alpha: 1
        )
    }
}
#endif
