import { type KeyboardEvent } from 'react'

type DslEditorProps = {
  value: string
  onChange: (value: string) => void
}

const indentSelection = (source: string, start: number, end: number) => {
  const lineStart = source.lastIndexOf('\n', Math.max(0, start - 1)) + 1
  const lineEnd = source.indexOf('\n', end)
  const selectionEnd = lineEnd === -1 ? source.length : lineEnd
  const selected = source.slice(lineStart, selectionEnd)
  const indented = selected
    .split('\n')
    .map(line => `  ${line}`)
    .join('\n')
  const next = source.slice(0, lineStart) + indented + source.slice(selectionEnd)
  const delta = indented.length - selected.length
  return { next, start: start + 2, end: end + delta }
}

const outdentSelection = (source: string, start: number, end: number) => {
  const lineStart = source.lastIndexOf('\n', Math.max(0, start - 1)) + 1
  const lineEnd = source.indexOf('\n', end)
  const selectionEnd = lineEnd === -1 ? source.length : lineEnd
  const selected = source.slice(lineStart, selectionEnd)
  const lines = selected.split('\n')
  let removed = 0
  const outdented = lines
    .map((line, idx) => {
      if (line.startsWith('  ')) {
        removed += 2
        return line.slice(2)
      }
      if (line.startsWith('\t')) {
        removed += 1
        return line.slice(1)
      }
      if (idx === 0 && lineStart < start && line.startsWith(' ')) {
        removed += 1
        return line.slice(1)
      }
      return line
    })
    .join('\n')
  const next = source.slice(0, lineStart) + outdented + source.slice(selectionEnd)
  const startShift = lines[0].startsWith('  ') ? 2 : lines[0].startsWith('\t') || lines[0].startsWith(' ') ? 1 : 0
  const nextStart = Math.max(lineStart, start - startShift)
  const nextEnd = Math.max(nextStart, end - removed)
  return { next, start: nextStart, end: nextEnd }
}

export default function DslEditor({ value, onChange }: DslEditorProps) {
  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== 'Tab') return
    event.preventDefault()
    const target = event.currentTarget
    const start = target.selectionStart
    const end = target.selectionEnd
    if (event.shiftKey) {
      const result = outdentSelection(value, start, end)
      onChange(result.next)
      requestAnimationFrame(() => {
        target.selectionStart = result.start
        target.selectionEnd = result.end
      })
      return
    }
    if (start === end) {
      const next = `${value.slice(0, start)}  ${value.slice(end)}`
      onChange(next)
      requestAnimationFrame(() => {
        target.selectionStart = start + 2
        target.selectionEnd = start + 2
      })
      return
    }
    const result = indentSelection(value, start, end)
    onChange(result.next)
    requestAnimationFrame(() => {
      target.selectionStart = result.start
      target.selectionEnd = result.end
    })
  }

  return (
    <div className="dsl-editor">
      <textarea
        className="dsl-editor-input"
        value={value}
        onChange={event => onChange(event.target.value)}
        onKeyDown={onKeyDown}
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        aria-label="Policy DSL editor"
      />
    </div>
  )
}

