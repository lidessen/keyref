// Shared visual primitives for the cool editorial layout: the flat page
// backdrop, the brand mark, hairline-ruled blocks, bare glyphs, section
// labels, status text, result heroes and the two button styles.
//
// Keep these presentation-only — accessibility labels belong to the screens
// that use them.
//
// There is deliberately nothing decorative here: no gradient, no glow, no
// shadow, no rounded card. Depth comes from hairlines and whitespace only
// (docs/ios-ui.md §3.8).
import SwiftUI

// MARK: - backdrop

/// The page itself: one flat colour, edge to edge.
struct KeyrefBackdrop: View {
    var body: some View {
        KeyrefTheme.background
            .ignoresSafeArea()
    }
}

// MARK: - brand mark

/// The mark: a hairline circle and a key. Flat, no glow — the amber is a
/// signal, not a light source.
struct BrandMark: View {
    var size: CGFloat = 64

    var body: some View {
        ZStack {
            Circle()
                .strokeBorder(KeyrefTheme.foreground.opacity(0.22), lineWidth: 1)
                .frame(width: size, height: size)
            Image(systemName: "key.fill")
                .font(.system(size: size * 0.34, weight: .medium))
                .foregroundStyle(KeyrefTheme.accent)
                .rotationEffect(.degrees(-45))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: - blocks

/// A group of content separated by hairlines above and below. No fill, no
/// corners, no shadow — this is what replaced the old card.
struct KeyrefBlock<Content: View>: View {
    var padding: CGFloat
    var content: Content

    init(padding: CGFloat = 14, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, padding)
            .overlay(alignment: .top) { rule }
            .overlay(alignment: .bottom) { rule }
    }

    private var rule: some View {
        Rectangle()
            .fill(KeyrefTheme.hairline)
            .frame(height: 1)
    }
}

// MARK: - iconography

/// A glyph inside a hairline circle. The app's one "figure" shape for
/// empty and error states — a drawn circle, never a filled disc.
struct KeyrefGlyphCircle: View {
    let systemName: String
    var tint: Color = KeyrefTheme.foreground
    var size: CGFloat = 96

    var body: some View {
        ZStack {
            Circle()
                .strokeBorder(tint.opacity(0.25), lineWidth: 1)
                .frame(width: size, height: size)
            Image(systemName: systemName)
                .font(.system(size: size * 0.32, weight: .light))
                .foregroundStyle(tint)
        }
    }
}

/// A bare glyph. The old version drew a tinted rounded tile; the type is
/// carried by the shape and the label beside it, not by a colour chip.
struct IconGlyph: View {
    let systemName: String
    var tint: Color = KeyrefTheme.foreground
    var size: CGFloat = 20

    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: size, weight: .medium))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// Item type glyph (§2.4 badge families): key / ticket / lock / note / box.
/// Monochrome on purpose — colour-coding by type would break the one-signal
/// rule the rest of the palette runs on.
struct ItemTypeGlyph: View {
    let type: String
    var size: CGFloat = 20

    var body: some View {
        IconGlyph(systemName: symbol, tint: KeyrefTheme.foreground, size: size)
    }

    private var symbol: String {
        switch type {
        case "api_key": return "key.fill"
        case "token": return "ticket.fill"
        case "password": return "lock.fill"
        case "note": return "note.text"
        default: return "shippingbox.fill"
        }
    }
}

// MARK: - labels & status

/// A short notice: a tinted glyph and one or two lines of text, held
/// between two hairlines. The tint lives on the glyph, not on a coloured
/// card.
struct KeyrefNotice: View {
    let systemName: String
    var tint: Color = KeyrefTheme.warning
    let text: String
    var emphasis = false

    var body: some View {
        KeyrefBlock {
            HStack(alignment: .top, spacing: 9) {
                IconGlyph(systemName: systemName, tint: tint, size: 15)
                Text(text)
                    .font(emphasis ? .footnote.weight(.medium) : .footnote)
                    .foregroundStyle(KeyrefTheme.foreground)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// Small section label. Chinese copy keeps its case; the tracking does the
/// work.
struct KeyrefSectionLabel: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .tracking(1.1)
            .foregroundStyle(KeyrefTheme.muted)
    }
}

/// Status as plain text, optionally with a dot. The old version was a
/// tinted capsule; a status is a word, not a badge.
struct StatusText: View {
    let text: String
    var tint: Color = KeyrefTheme.muted
    var showDot = false

    var body: some View {
        HStack(spacing: 5) {
            if showDot {
                Circle()
                    .fill(tint)
                    .frame(width: 5, height: 5)
            }
            Text(text)
                .font(.caption2.weight(.semibold))
        }
        .foregroundStyle(tint)
    }
}

// MARK: - result screens

/// The shared completion / failure face used by pairing, revocation,
/// recovery, creation and deletion so every "ending" reads the same. The
/// figure is the same hairline circle as the empty states and the brand mark
/// — one shape for every "figure" in the app.
struct ResultHero: View {
    let systemName: String
    var tint: Color = KeyrefTheme.success
    let title: String
    var message: String?
    var footnote: String?

    var body: some View {
        VStack(spacing: 14) {
            KeyrefGlyphCircle(systemName: systemName, tint: tint, size: 88)
                .symbolEffect(.bounce, value: title)
            Text(title)
                .font(.title2.weight(.semibold))
                .multilineTextAlignment(.center)
            if let message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            if let footnote {
                Text(footnote)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 2)
            }
        }
    }
}

// MARK: - buttons

/// The brand's main action: a flat block of foreground colour with the page
/// colour on top. No gradient, no glow, no border — the reference is a
/// single fill and a moderate radius (Mobbin: Whatnot / X / Luma).
struct KeyrefPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(KeyrefTheme.background)
            .padding(.vertical, 15)
            .frame(maxWidth: .infinity)
            .background {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(KeyrefTheme.foreground)
            }
            // 按下时压一层页面色——不用亮度调节，深浅两套配色都成立。
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(KeyrefTheme.background.opacity(configuration.isPressed ? 0.16 : 0))
            }
            .opacity(isEnabled ? 1 : 0.35)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// The quiet companion: the same shape, outlined instead of filled.
struct KeyrefSecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .foregroundStyle(KeyrefTheme.foreground)
            .padding(.vertical, 15)
            .frame(maxWidth: .infinity)
            .background {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(KeyrefTheme.foreground.opacity(configuration.isPressed ? 0.08 : 0))
            }
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(KeyrefTheme.foreground.opacity(0.22), lineWidth: 1)
            }
            .opacity(isEnabled ? 1 : 0.35)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

// MARK: - list styling

extension View {
    /// Flat page + hairline separators. System chrome (navigation bar, tab
    /// bar) stays system (ios-ui §3.8).
    ///
    /// `.listStyle(.plain)` is what removes iOS 26's rounded section cards:
    /// in the grouped style every section sits on its own glassy plate, and
    /// `listRowBackground` cannot take that plate away. Plain style also
    /// gives every row the same insets, so a list and a form read as the
    /// same page.
    func keyrefListSurface() -> some View {
        self
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background(KeyrefBackdrop())
            .listRowBackground(Color.clear)
            .listRowSeparatorTint(KeyrefTheme.hairline)
    }
}
