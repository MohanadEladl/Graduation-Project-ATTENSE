import { useEffect, useRef, useImperativeHandle, forwardRef } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'

/**
 * TerminalView — thin wrapper around xterm.js.
 *
 * Local line editing:
 *   - user types characters → they appear locally
 *   - Enter → entire line is sent via props.onSubmit(line)
 *   - ↑ / ↓ cycle through history
 *   - Backspace deletes
 *   - Ctrl-C clears current line
 *   - Ctrl-L clears screen
 *
 * Server output and server prompts are written verbatim via writeOutput()
 * and setPrompt() exposed through an imperative ref.
 */
const THEME = {
  background:    '#0c0f16',
  foreground:    '#e6e8ee',
  cursor:        '#ff2b3a',
  cursorAccent:  '#0c0f16',
  selectionBackground: 'rgba(255,43,58,0.25)',
  black:         '#0c0f16',
  red:           '#ff2b3a',
  green:         '#2ee39a',
  yellow:        '#ffa724',
  blue:          '#6da9ff',
  magenta:       '#9a6bff',
  cyan:          '#7ad9ff',
  white:         '#e6e8ee',
  brightBlack:   '#4a5363',
  brightRed:     '#ff5b66',
  brightGreen:   '#5cf0b3',
  brightYellow:  '#ffc062',
  brightBlue:    '#94c1ff',
  brightMagenta: '#b690ff',
  brightCyan:    '#9ae4ff',
  brightWhite:   '#ffffff',
}

export const TerminalView = forwardRef(function TerminalView(
  { onSubmit, className = '' },
  ref
) {
  const hostRef     = useRef(null)
  const termRef     = useRef(null)
  const fitRef      = useRef(null)
  const lineRef     = useRef('')      // currently-typed line
  const promptRef   = useRef('')      // most recent server-provided prompt
  const historyRef  = useRef([])
  const histIdxRef  = useRef(-1)      // -1 = typing fresh
  const draftRef    = useRef('')

  // Setup xterm once
  useEffect(() => {
    if (!hostRef.current) return
    const term = new Terminal({
      cursorBlink: true,
      cursorStyle: 'bar',
      convertEol:  true,
      fontFamily:  '"JetBrains Mono", ui-monospace, monospace',
      fontSize:    13,
      lineHeight:  1.35,
      letterSpacing: 0.2,
      scrollback:  5000,
      theme:       THEME,
      allowProposedApi: true,
    })
    const fit   = new FitAddon()
    const links = new WebLinksAddon()
    term.loadAddon(fit)
    term.loadAddon(links)
    term.open(hostRef.current)
    fit.fit()

    termRef.current = term
    fitRef.current  = fit

    // Focus the terminal when the host is clicked
    const focus = () => term.focus()
    hostRef.current.addEventListener('click', focus)

    // Handle keystrokes: local line editing
    const disposable = term.onData((data) => {
      for (const ch of data) {
        const code = ch.charCodeAt(0)
        // Enter
        if (ch === '\r' || ch === '\n') {
          term.write('\r\n')
          const line = lineRef.current
          if (line.trim().length) {
            historyRef.current.push(line)
            if (historyRef.current.length > 500) historyRef.current.shift()
          }
          histIdxRef.current = -1
          draftRef.current = ''
          lineRef.current = ''
          onSubmit?.(line)
          continue
        }
        // Backspace (DEL 0x7f or BS 0x08)
        if (code === 0x7f || code === 0x08) {
          if (lineRef.current.length > 0) {
            lineRef.current = lineRef.current.slice(0, -1)
            term.write('\b \b')
          }
          continue
        }
        // Ctrl-C
        if (code === 0x03) {
          term.write('^C\r\n')
          lineRef.current = ''
          histIdxRef.current = -1
          draftRef.current = ''
          writePrompt()
          continue
        }
        // Ctrl-L
        if (code === 0x0c) {
          term.clear()
          writePrompt()
          term.write(lineRef.current)
          continue
        }
        // Escape sequences — handle arrow keys
        if (code === 0x1b) {
          // xterm sends escape sequences as one string chunk normally, but
          // with codepoint iteration we see them char-by-char. Drop escapes
          // we don't know; the subsequent chars will be harmless letters.
          continue
        }
        // Printable
        if (code >= 0x20) {
          lineRef.current += ch
          term.write(ch)
        }
      }
    })

    // Arrow keys via onKey for reliability
    const keyDisposable = term.onKey(({ domEvent }) => {
      const term = termRef.current
      if (!term) return
      if (domEvent.key === 'ArrowUp' || domEvent.key === 'ArrowDown') {
        domEvent.preventDefault?.()
        const hist = historyRef.current
        if (!hist.length) return

        // Save current draft on first press
        if (histIdxRef.current === -1) draftRef.current = lineRef.current

        let idx = histIdxRef.current
        if (domEvent.key === 'ArrowUp') {
          idx = idx === -1 ? hist.length - 1 : Math.max(0, idx - 1)
        } else {
          if (idx === -1) return
          idx = idx + 1
          if (idx >= hist.length) idx = -1
        }

        // Erase the current line text on screen
        for (let i = 0; i < lineRef.current.length; i++) term.write('\b \b')
        const newLine = idx === -1 ? draftRef.current : hist[idx]
        term.write(newLine)
        lineRef.current = newLine
        histIdxRef.current = idx
      }
    })

    // Write initial hint
    term.writeln('\x1b[2;37m  connecting to attense shell…\x1b[0m')

    // Resize handling
    const ro = new ResizeObserver(() => { try { fit.fit() } catch {} })
    ro.observe(hostRef.current)

    function writePrompt() {
      if (promptRef.current) term.write(promptRef.current)
    }

    return () => {
      disposable.dispose()
      keyDisposable.dispose()
      ro.disconnect()
      hostRef.current?.removeEventListener('click', focus)
      term.dispose()
      termRef.current = null
      fitRef.current  = null
    }
  }, [onSubmit])

  useImperativeHandle(ref, () => ({
    writeOutput(line) {
      const term = termRef.current
      if (!term) return
      // Server lines may or may not include their own trailing newline.
      // Normalize: one line per call, with CRLF for xterm.
      term.writeln(line)
    },
    setPrompt(prompt) {
      promptRef.current = prompt || ''
      const term = termRef.current
      if (!term) return
      // Write prompt so the user has something to type against.
      // Only redraw if the cursor is at a fresh line (lineRef empty).
      if (lineRef.current.length === 0) {
        term.write(promptRef.current)
      }
    },
    refit() {
      try { fitRef.current?.fit() } catch {}
    },
    clear() {
      termRef.current?.clear()
    },
    focus() {
      termRef.current?.focus()
    },
    paste(text) {
      const term = termRef.current
      if (!term) return
      for (const ch of text) {
        if (ch === '\n' || ch === '\r') continue
        lineRef.current += ch
        term.write(ch)
      }
    },
  }), [])

  return (
    <div
      ref={hostRef}
      className={
        'h-full w-full rounded-md bg-attense-panel border border-attense-border ' +
        'shadow-inset-hair overflow-hidden ' + className
      }
      aria-label="Interactive lab terminal"
      role="application"
    />
  )
})
