# WheelyTrails Design System Documentation

**Version:** 1.3  
**Last Updated:** December 18, 2025  
**Design Framework:** Google Material Design 3 (Material You)  
**CSS Framework:** Tailwind CSS 3.4+  
**Target Platforms:** Progressive Web App (PWA) - iOS, Android, Desktop

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Color System](#color-system)
3. [Typography](#typography)
4. [Layout & Spacing](#layout--spacing)
5. [Components](#components)
6. [Motion & Transitions](#motion--transitions)
7. [Elevation & Shadows](#elevation--shadows)
8. [Accessibility](#accessibility)
9. [Dark Mode](#dark-mode)
10. [Responsive Design](#responsive-design)
11. [Implementation Guide](#implementation-guide)
12. [Component Library](#component-library)
13. [Design Tokens Reference](#design-tokens-reference)
14. [Changelog](#changelog)
15. [Resources](#resources)
16. [Notes for Developers](#notes-for-developers)

---

## Design Philosophy

### Core Principles

**Material Design 3 (Material You)**
- **Personalization:** Dynamic color system adapts to user preferences
- **Expressiveness:** Bold, colorful, and optimistic visual language
- **Accessibility:** WCAG 2.1/2.2 compliance for contrast and interaction
- **Adaptability:** Seamless experience across mobile, tablet, and desktop

**WheelyTrails Brand Identity**
- **Inclusive:** Accessible outdoor experiences for wheelchair users
- **Natural:** Green color palette reflecting trails and nature
- **Trustworthy:** Clean, professional interface with clear information hierarchy
- **Community-Driven:** Social features with user-generated content

### Design Goals

1. ✅ **Native App Feel:** Fixed header/footer, bottom navigation, smooth transitions  
2. ✅ **Mobile-First:** Optimized for touch interactions and small screens  
3. ✅ **Performance:** Minimal dependencies, optimized assets, fast load times  
4. ✅ **Offline-Capable:** PWA features for offline trail viewing  
5. ✅ **Accessible:** Screen reader support, high contrast modes, keyboard navigation

---

## Color System

(unchanged — see previous sections for full token list)

---

## Typography

(unchanged — see previous sections for full type scale and Tailwind mapping)

---

## Layout & Spacing

### Material 3 Grid System

(unchanged)

### Spacing Scale

(unchanged)

### Layout Patterns

#### Mobile (< 640px)
- Single column content
- Bottom navigation (5 items max)
- Fixed header (64px height, MD3 standard)
- Fixed footer (TabBar) uses 4rem (h-16) height and reserves safe area
- Content padding: 16px horizontal

> Note: The Top App Bar height has been standardized to MD3 recommended *64px* (`min-h-[64px]`) throughout the client to keep content offsets consistent across layouts and with `pt-16` on the main content container.

---

## Components

### Material 3 Component Specifications

#### Top App Bar (NavBar.razor)

**Container**
- Height: 64px minimum (MD3 standard)
- Background: `bg-[var(--md-sys-color-surface-container)]` — now rendered with a subtle translucency when appropriate to allow a layered UI
- Visual polish: `backdrop-blur-sm` + slight translucency for a layered native-app feel on supported platforms
- Border: `border-b border-[var(--md-sys-color-outline-variant)]`
- Elevation: `shadow-elevation-3` (slightly stronger to separate from content)
- Position: Fixed top
- Z-index: 20

**Desktop Layout (>= 1024px)**  
- Logo: Left side  
- Navigation links: Center (desktop)  
- Theme toggle + Auth: Right side

**Mobile Layout (< 1024px)**  
- Hamburger menu: Material Symbol `menu` icon  
- Drawer navigation: Slides in from left — drawer is fixed between `top: 0` and `bottom: 4rem` to avoid being obscured by the TabBar on mobile (`max-lg:bottom-16`), and `overflow-y:auto` to enable internal scrolling.  
- Close button: Material Symbol `close` icon  
- Mobile drawer background: `bg-[var(--md-sys-color-surface)]`  
- Mobile drawer elevation: `shadow-elevation-3`  

**Navigation Links**
- Active state: `text-[var(--md-sys-color-primary)]` with `border-b-2`
- Inactive state: `text-[var(--md-sys-color-on-surface)]` with hover to primary
- Font weight: Semibold for active, regular for inactive

**User Menu Dropdown**
- Background: `bg-[var(--md-sys-color-surface-container-high)]`
- Border radius: 12px (`rounded-xl`)
- Elevation: `shadow-elevation-3`
- Items: Profile, Settings, Logout
- Logout button: `text-[var(--md-sys-color-error)]` with error container hover

> Implementation notes:
> - The mobile drawer now reserves the TabBar area (4rem / `h-16`) to prevent clipping. If TabBar height changes, update the drawer bottom inset (`max-lg:bottom-16`) or use a CSS variable for the TabBar height.

#### Bottom Navigation / Tab Bar (TabBar.razor)

**Container**
- Height: 4rem (`h-16`, 64px) — aligned with mobile safe-area and touch target recommendations
- Background: `bg-[var(--md-sys-color-surface-container)]`
- Elevation: `shadow-elevation-2`
- Items: 3-5 destinations

**Floating Primary Action (Add)**
- The primary Add CTA is a floating action style in the centre of the TabBar:
  - Size: `w-14 h-14` (56px) — square so `rounded-full` produces a perfect circle
  - Background: `bg-[var(--md-sys-color-primary)]`
  - Icon color: `text-[var(--md-sys-color-on-primary)]`
  - Box: `rounded-full flex items-center justify-center shadow-elevation-4 ring-2 ring-[var(--md-sys-color-surface)]`
  - Microinteraction: `hover:scale-105 transition-transform duration-150`
  - Accessibility: large enough to satisfy 48×48 touch target; focus-visible ring added
- Ensure equal `width == height` to make the Add button perfectly round.

**Nav Item (Inactive)**
- Icon: 24px, `text-[var(--md-sys-color-on-surface-variant)]`
- Label: 12px, `text-label-medium`

**Nav Item (Active)**
- Highlight: pill background `bg-[var(--md-sys-color-secondary-container)]`
- Icon/text: `text-[var(--md-sys-color-on-secondary-container)]`

---

## Motion & Transitions

(unchanged — see previous sections)

---

## Elevation & Shadows

(unchanged — added slight increase for top-bar polish to `shadow-elevation-3` where noted)

---

## Accessibility

(unchanged — continue to follow WCAG and touch-target guidelines)

---

## Dark Mode

(unchanged — ThemeToggle remains the entry point for dark mode; contrast selector pending final decision)

---

## Responsive Design

(unchanged — updated Top App Bar height and TabBar height called out in Layout and Components sections)

---

## Implementation Guide

(unchanged — keep build steps, environment, and Tailwind build guidance)

---

## Component Library

### Reusable Blazor Components

#### ThemeToggle.razor

**Location:** `WT.Client/Components/ThemeToggle.razor`  
(Notes unchanged — contrast selector remains present in UI but is non-destructive; implement `themeManager.setContrast` if enabling contrast files.)

#### NavBar.razor

**Location:** `WT.Client/Layout/NavBar.razor`  

**Updates**
- NavBar now uses `min-h-[64px]` (MD3 standard)
- Visual polish applied:
  - `backdrop-blur-sm` with light translucency for layered look
  - Increased elevation to `shadow-elevation-3` to distinguish from content
- Mobile drawer adjusted to end above TabBar (drawer `bottom: 4rem` / `max-lg:bottom-16`) and allow internal scrolling (`overflow-y-auto`) so footer controls are reachable.

#### TabBar.razor

**Location:** `WT.Client/Layout/TabBar.razor`  

**Updates**
- TabBar is `h-16` (4rem) and reserved as the mobile footer.
- Add (primary) action is implemented as a circular floating action control:
  - `w-14 h-14 rounded-full flex items-center justify-center` plus shadow and ring
  - Hover & focus interactions for discoverability and accessibility

#### MainLayout.razor

- `pt-16` is used to offset content for a 64px NavBar (no change required if NavBar is set to `min-h-[64px]`).

---

## Design Tokens Reference

(unchanged)

---

## Changelog

### Version 1.3 (December 18, 2025)

**Visual & UX polish**
- ✅ Standardized Top App Bar height to MD3 recommended `64px` (`min-h-[64px]`).
- ✅ Applied subtle backdrop blur and translucency to the NavBar for better depth and polish (`backdrop-blur-sm` + translucent surface).
- ✅ Increased NavBar elevation to `shadow-elevation-3` for clearer separation from content.
- ✅ Fixed mobile drawer clipping: drawer now reserves TabBar height — drawer fixed from top to `bottom: 4rem` (`max-lg:bottom-16`) and uses `overflow-y:auto` so footer controls (Login/Sign Up, Settings) are reachable.
- ✅ Made the TabBar Add / primary action perfectly round and prominent:
  - enforced square container `w-14 h-14` + `rounded-full` + shadow + ring + hover scale microinteraction.
- ✅ Ensured consistent TabBar height `h-16` (4rem) and updated guidance to keep drawer inset in sync.
- ✅ Minor accessibility improvements: focus-visible ring, increased touch target clarity for floating Add action.

**Notes**
- If TabBar height changes in future, update the mobile drawer bottom inset to match (or use a CSS variable to keep both in sync).
- Contrast selector in `ThemeToggle.razor` remains present; consider implementing `themeManager.setContrast` and adding MD3 contrast CSS files when ready.

### Version 1.2 (previous)
- Material Design 3 integration and other updates (see previous changelog entries).

---

## Resources

(unchanged)

---

## Notes for Developers

### Key implementation reminders
- Keep the NavBar `min-h-[64px]` and the MainLayout `pt-16` aligned.
- Mobile drawer should stop above TabBar to avoid clipping: use `max-lg:bottom-16` or a CSS variable representing the TabBar height.
- For the Add (primary) action, always enforce width == height so `rounded-full` yields a perfect circle (recommended `w-14 h-14`).
- Rebuild Tailwind CSS after updating classes (`npm run build:css`) so utilities are included in the compiled output.

---

**End of Design System Documentation**