// ShieldMail v2 — Système de thèmes partagé
// Chargé AVANT les scripts popup/options/dashboard/content — expose des globals simples
// (pas de modules ES pour rester compatible content scripts + pages d'extension).
'use strict';

// ── Palettes ──────────────────────────────────────────────────────
// Chaque thème définit des couleurs (hex + "r,g,b" pour les rgba()).
const SM_THEMES = {
  cyber: {
    label: 'Cyber Teal',
    swatch: ['#070B11', '#00D4B4', '#F5A623'],
    vars: {
      '--sm-bg': '#070B11', '--sm-bg2': '#0D1520', '--sm-bg3': '#111D2E',
      '--sm-border': '#1E3048',
      '--sm-accent': '#00D4B4', '--sm-accent-rgb': '0,212,180',
      '--sm-ham': '#00D4B4', '--sm-ham-rgb': '0,212,180',
      '--sm-spam': '#FF5B3A', '--sm-spam-rgb': '255,91,58',
      '--sm-phish': '#F5A623', '--sm-phish-rgb': '245,166,35',
      '--sm-text': '#F0F4F8', '--sm-text-mid': '#8AAFC8', '--sm-text-dim': '#5C7A96',
      '--sm-text-dim-rgb': '92,122,150',
    },
  },
  aurora: {
    label: 'Aurora Violette',
    swatch: ['#0B0714', '#B37FFF', '#3DDC97'],
    vars: {
      '--sm-bg': '#0B0714', '--sm-bg2': '#150D24', '--sm-bg3': '#1E1433',
      '--sm-border': '#332154',
      '--sm-accent': '#B37FFF', '--sm-accent-rgb': '179,127,255',
      '--sm-ham': '#3DDC97', '--sm-ham-rgb': '61,220,151',
      '--sm-spam': '#FF5C8A', '--sm-spam-rgb': '255,92,138',
      '--sm-phish': '#FFC15C', '--sm-phish-rgb': '255,193,92',
      '--sm-text': '#F3EEFB', '--sm-text-mid': '#B7A3D9', '--sm-text-dim': '#7C6A9E',
      '--sm-text-dim-rgb': '124,106,158',
    },
  },
  arctic: {
    label: 'Arctic Clair',
    swatch: ['#F5F7FA', '#2563EB', '#0E9F6E'],
    vars: {
      '--sm-bg': '#F5F7FA', '--sm-bg2': '#FFFFFF', '--sm-bg3': '#EDF1F6',
      '--sm-border': '#D7DFE9',
      '--sm-accent': '#2563EB', '--sm-accent-rgb': '37,99,235',
      '--sm-ham': '#0E9F6E', '--sm-ham-rgb': '14,159,110',
      '--sm-spam': '#E11D48', '--sm-spam-rgb': '225,29,72',
      '--sm-phish': '#D97706', '--sm-phish-rgb': '217,119,6',
      '--sm-text': '#0F172A', '--sm-text-mid': '#475569', '--sm-text-dim': '#94A3B8',
      '--sm-text-dim-rgb': '148,163,184',
    },
  },
  amber: {
    label: 'Braise Ambrée',
    swatch: ['#120B06', '#FF9F45', '#7BC96F'],
    vars: {
      '--sm-bg': '#120B06', '--sm-bg2': '#1C120A', '--sm-bg3': '#291A0E',
      '--sm-border': '#4A2F17',
      '--sm-accent': '#FF9F45', '--sm-accent-rgb': '255,159,69',
      '--sm-ham': '#7BC96F', '--sm-ham-rgb': '123,201,111',
      '--sm-spam': '#FF5C5C', '--sm-spam-rgb': '255,92,92',
      '--sm-phish': '#FFD166', '--sm-phish-rgb': '255,209,102',
      '--sm-text': '#FBF1E6', '--sm-text-mid': '#C9A57B', '--sm-text-dim': '#9C7C5C',
      '--sm-text-dim-rgb': '156,124,92',
    },
  },
};

// ── Polices (indépendantes du thème de couleur) ────────────────────
const SM_FONTS = {
  moderne: {
    label: 'Moderne (sans-serif)',
    main: "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'DM Sans',sans-serif",
    mono: "ui-monospace,'SFMono-Regular',Consolas,'Liberation Mono',monospace",
  },
  tech: {
    label: 'Technique (monospace)',
    main: "'JetBrains Mono',ui-monospace,'Cascadia Code',Consolas,monospace",
    mono: "'JetBrains Mono',ui-monospace,'Cascadia Code',Consolas,monospace",
  },
  classique: {
    label: 'Classique (serif)',
    main: "Georgia,'Iowan Old Style','Times New Roman',serif",
    mono: "ui-monospace,'SFMono-Regular',Consolas,monospace",
  },
};

const SM_DEFAULT_THEME = 'cyber';
const SM_DEFAULT_FONT = 'moderne';

// Applique les variables CSS d'un thème + d'une police sur un élément racine
// (document.documentElement pour les pages d'extension, idem pour le contenu
// injecté puisque les variables custom traversent le DOM de la page hôte
// sans jamais entrer en collision — préfixe --sm- dédié).
function smApplyTheme(root, themeKey, fontKey) {
  const theme = SM_THEMES[themeKey] || SM_THEMES[SM_DEFAULT_THEME];
  const font = SM_FONTS[fontKey] || SM_FONTS[SM_DEFAULT_FONT];
  Object.entries(theme.vars).forEach(([k, v]) => root.style.setProperty(k, v));
  root.style.setProperty('--sm-font-main', font.main);
  root.style.setProperty('--sm-font-mono', font.mono);
  root.setAttribute('data-sm-theme', themeKey || SM_DEFAULT_THEME);
}

// Construit un petit sélecteur de thème + police réutilisable (grille de pastilles).
// onChange(themeKey, fontKey) est appelé à chaque sélection.
function smBuildThemePicker(container, current, onChange) {
  const state = { theme: current.theme || SM_DEFAULT_THEME, font: current.font || SM_DEFAULT_FONT };
  container.innerHTML = `
    <div class="sm-tp-row" id="sm-tp-themes"></div>
    <div class="sm-tp-fonts" id="sm-tp-fonts"></div>`;
  const themesEl = container.querySelector('#sm-tp-themes');
  const fontsEl = container.querySelector('#sm-tp-fonts');

  Object.entries(SM_THEMES).forEach(([key, t]) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'sm-tp-swatch' + (key === state.theme ? ' active' : '');
    btn.title = t.label;
    btn.innerHTML = `<span class="sm-tp-dots">${t.swatch.map(c => `<i style="background:${c}"></i>`).join('')}</span><small>${t.label}</small>`;
    btn.addEventListener('click', () => {
      state.theme = key;
      themesEl.querySelectorAll('.sm-tp-swatch').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      onChange(state.theme, state.font);
    });
    themesEl.appendChild(btn);
  });

  Object.entries(SM_FONTS).forEach(([key, f]) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'sm-tp-font' + (key === state.font ? ' active' : '');
    btn.style.fontFamily = f.main;
    btn.textContent = 'Aa · ' + f.label;
    btn.addEventListener('click', () => {
      state.font = key;
      fontsEl.querySelectorAll('.sm-tp-font').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      onChange(state.theme, state.font);
    });
    fontsEl.appendChild(btn);
  });
}
