import { DocsThemeConfig } from 'nextra-theme-docs'

const config: DocsThemeConfig = {
  logo: <span style={{ fontWeight: 700 }}>🪢 Reins</span>,
  project: {
    link: 'https://github.com/pegasi-ai/reins',
  },
  docsRepositoryBase: 'https://github.com/pegasi-ai/reins/tree/main/docs',
  useNextSeoProps() {
    return { titleTemplate: '%s – Reins' }
  },
  head: (
    <>
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <meta name="description" content="Security controls for AI agents." />
    </>
  ),
  footer: {
    text: (
      <span>
        Apache 2.0 {new Date().getFullYear()} ©{' '}
        <a href="https://pegasi.ai" target="_blank">Pegasi AI</a>
      </span>
    ),
  },
}

export default config
