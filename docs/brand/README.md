# certloom brand

The mark is a shield holding a certificate chain: two certificates behind
(root and intermediate) and the leaf in front with a seal.

| File | Use |
|---|---|
| `certloom-mark.svg` | Default mark on light backgrounds |
| `certloom-mark-dark.svg` | On dark backgrounds (white shield) |
| `certloom-mark-mono.svg` | One colour plus white (print, stamps) |
| `certloom-favicon.svg` | Browser tabs and anything under 32 px; no text lines, follows the OS light/dark setting |
| `certloom-mark-512.png` | Avatars (GitHub organization, Ansible Galaxy, registries), transparent |
| `certloom-og.png` | Social preview, 1280x640 (GitHub: Settings > General > Social preview) |

The web UI serves copies of the mark and favicon from `internal/web/static`.
Change them here first, then copy them there.

## Colours

| Name | Hex | Use |
|---|---|---|
| Navy | `#0B1F3A` | Shield, text lines, wordmark, dark backgrounds |
| Teal | `#0FA3A3` | Back certificate, seal, ribbons |
| Light teal | `#5FD3D3` | Middle certificate, accents on navy |
| White | `#FFFFFF` | Front certificate; shield and wordmark on navy |

## Wordmark

`certloom`, always lowercase, in Inter SemiBold (SIL Open Font License) with
-1% letter spacing, to the right of the mark. The mark is about 1.4 times the
cap height of the wordmark. Leave clear space of at least half the mark's width
on every side.

## Do not

- Recolour the shield teal or change the order of the certificate colours.
- Rotate, stretch, outline, or add shadows or gradients to the mark.
- Use the full mark below 32 px; use the favicon instead.
