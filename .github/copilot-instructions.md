---
applyTo: "**"
---

# Global Coding Rules

- Do not use emojis in any output.
- Do not use emojis in code, comments, or explanations.
- Do not use basic comments on SQL queries, like "# Your INSERT query" etc
- Do not add comments that just repeat what the code does. Only add if there is really something extra to explain.
- Use English for code comments and technical documentation.
- Always use type hints for function parameters and return values. But types need to be generic not not too specific. But avoid using Any unless absolutely necessary.
- Write code that is easy to read and understand. Prioritize clarity over cleverness.
- Follow consistent naming conventions for variables, functions, classes, and other identifiers.
- Write modular code by breaking down complex problems into smaller, manageable functions or classes.
- Avoid deep nesting of code blocks. Refactor into smaller functions if necessary.
- Optimize code for performance only when necessary, and avoid premature optimization.
- Handle errors gracefully and continue processing remaining items instead of exiting.
- Make sure that each function has a maybe not single responsibility, but at least a clear purpose and does not try to do too many things at once.
- Do not make duplicate logic or functions. Reuse existing code where possible.
