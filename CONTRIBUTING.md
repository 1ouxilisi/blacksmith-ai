# Contributing to BlacksmithAI

Thank you for your interest in contributing to BlacksmithAI!

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue and include:
- A clear description of the bug
- Steps to reproduce
- Expected behavior
- Actual behavior
- Screenshots if applicable

### Suggesting Features

We welcome feature suggestions! Please open an issue and include:
- A clear description of the feature
- Why it would be useful
- How it should work

### Pull Requests

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run the tests: `python health_check.py`
5. Commit your changes: `git commit -m 'Add your feature'`
6. Push to the branch: `git push origin feature/your-feature`
7. Open a Pull Request

## Code Style

- Follow PEP 8 for Python code
- Add comments for complex logic
- Write tests for new features

## Project Structure

```
blacksmithAI/
├── utils/           # Core modules
│   ├── owasp_llm_tester.py      # OWASP LLM Top 10
│   ├── owasp_agentic_tester.py  # OWASP Agentic Top 10
│   ├── rag_security_tester.py   # RAG security
│   ├── model_security_tester.py # Model security
│   ├── privacy_security_tester.py # Privacy security
│   ├── supply_chain_tester.py   # Supply chain security
│   ├── adversarial_attacks.py   # Adversarial attacks
│   ├── multi_turn_attacker.py   # Multi-turn attacks
│   ├── auto_attacker.py         # Auto attack generation
│   └── ...
├── web/             # Web Dashboard
├── cli.py           # Command line interface
└── health_check.py  # Health check
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
