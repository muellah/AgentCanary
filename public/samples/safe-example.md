---
name: format-code
description: Format code snippets as clean, readable markdown with syntax highlighting
user_invocable: true
---

# Format Code

When the user pastes code or asks you to format code, apply these rules:

## Steps

1. Detect the programming language from the code content
2. Wrap the code in a fenced code block with the correct language identifier
3. Fix indentation to use 2 spaces consistently
4. Add a brief comment explaining what the code does

## Example

Input: `const x=1;const y=2;console.log(x+y)`

Output:
```js
// Add two numbers and log the result
const x = 1;
const y = 2;
console.log(x + y);
```

## Constraints

- Do not modify the logic of the code
- Preserve all comments
- Do not add imports or dependencies
