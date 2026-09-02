# Zscaler AI Guard — NeMo Guardrails Library Plugin

This directory contains a library-format integration for contributing to the [NVIDIA NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) repository. Once merged, users can reference the flows directly without copying action files.

## Plugin Structure

```
zscaler_aiguard/
├── __init__.py    # Package init
├── actions.py     # System action: call_zscaler_aiguard_api
└── flows.co       # Flow definitions for input/output rails
```

## How to Submit

### 1. Fork and Clone

```bash
gh repo fork NVIDIA-NeMo/Guardrails --clone
cd Guardrails
```

### 2. Copy Plugin

```bash
cp -r zscaler_aiguard nemoguardrails/library/zscaler_aiguard
```

### 3. Usage (after merge)

Users would reference the flows in their `config.yml`:

```yaml
rails:
  input:
    flows:
      - zscaler aiguard moderation on input
  output:
    flows:
      - zscaler aiguard moderation on output
```

Environment variables:
```bash
export AIGUARD_API_KEY=your-api-key
export AIGUARD_CLOUD=us1   # optional, defaults to us1
```

### 4. Submit PR

```bash
git checkout -b feat/zscaler-aiguard-integration
git add nemoguardrails/library/zscaler_aiguard
git commit -m "feat: add Zscaler AI Guard library integration"
git push -u origin feat/zscaler-aiguard-integration
gh pr create --title "feat: Add Zscaler AI Guard library integration"
```

## Reference

- [ActiveFence integration](https://github.com/NVIDIA-NeMo/Guardrails/tree/develop/nemoguardrails/library/activefence) — reference library plugin
- [NeMo Guardrails docs](https://docs.nvidia.com/nemo/guardrails/latest/index.html)
