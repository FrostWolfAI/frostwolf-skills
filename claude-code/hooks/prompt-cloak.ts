import type { Register } from 'claude-code'

/**
 * Cloak personal data and secrets in a typed prompt before Claude reads it.
 *
 * A settings hook can only send a prompt as typed or refuse it, so the plugin's
 * UserPromptSubmit hook refuses a prompt that carries personal data. A mod can
 * replace the prompt, so this one asks the plugin's local service to cloak it
 * and passes the cloaked text on. The values stay in the service's vault, and
 * the plugin's other hooks put them back in tool calls and in what you read.
 *
 * The UserPromptSubmit hook still runs on what this passes on. It checks the
 * prompt's attached files, and it stays the one place a prompt is refused: when
 * anything here fails, the prompt goes on as typed and that hook decides, as it
 * did before this mod, so a failure here never sends a value unchecked.
 */

/** Where the service names its socket for each session; `src/pointer.ts` writes it. */
const POINTER_DIR = '.frostwolf/claude-code/sessions'

/** A session id that is safe to put in a file name, as `src/pointer.ts` requires. */
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/

/** Path of the service's prompt endpoint, `PROMPT_PATH` in `src/protocol.ts`. */
const PROMPT_URL = 'http://frostwolf/prompt'

type Answer =
  | { status: 'cloaked'; text: string; message: string }
  | { status: 'clean'; message: string | null }
  | { status: 'defer'; reason: string }

export const register: Register = (on) => {
  on('prompt.submit', async ($, e, next) => {
    // A slash command's text is not applied when rewritten, and a hidden prompt
    // that starts a turn takes no rewrite: both go on to the prompt hook.
    if (e.command !== undefined || e.isMeta === true || e.text.trim().length === 0) {
      return next(e)
    }

    const sessionId = await $.session.id()
    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'))
    if (home === undefined || !SESSION_ID.test(sessionId)) {
      return next(e)
    }

    let socket: string
    try {
      const pointer = JSON.parse(await $.fs.read(`${home}/${POINTER_DIR}/${sessionId}.json`)) as { socket?: unknown }
      if (typeof pointer.socket !== 'string') return next(e)
      socket = pointer.socket
    } catch {
      // No pointer: the service has not seen this session start.
      return next(e)
    }

    const response = await $.http.fetch(PROMPT_URL, {
      method: 'POST',
      socketPath: socket,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, cwd: await $.session.cwd(), text: e.text }),
    })
    if (!response.ok) return next(e)

    const answer = JSON.parse(response.text) as Answer
    if (answer.status === 'cloaked' && typeof answer.text === 'string') {
      $.ui.log(answer.message)
      return next({ ...e, text: answer.text })
    }
    if (answer.status === 'clean' && answer.message !== null) {
      $.ui.log(answer.message)
    }
    return next(e)
  }).catch(($, e, next) => next(e))
}
