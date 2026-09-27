---
description: 'Guidance for engineering CheckMK agent plugins, including coding standards, best practices, and testing recommendations.'
applyTo: '**'
---

# CheckMK Plugin Development Guidelines

Use these instructions when writing guidance, scripts, or documentation for Checkmk agent plugins, Checkmk special agents, Checkmk check plugins and integrations.

## General Principles

- Assume the reader has an understanding of Checkmk and its plugin architecture, but provide clear explanations for any complex concepts or specific implementation details.

## Testing and Validation

- Always create a devcontainer for testing your plugin in a consistent environment.
- Include unit tests for critical functions and components of your plugin.
- Use a Checkmk cloud edition latest version devcontainer for testing to ensure compatibility with the latest Checkmk features and updates. The plugin should be installed on the devcontainer and tested using the Checkmk agent within the container to validate its functionality and integration with Checkmk.
- Document the testing process and any specific test cases or scenarios that are important for validating the plugin's functionality and performance.

## Code Style and Formatting

- Follow the coding conventions and best practices for the programming language used in your plugin (e.g., Python, Shell, etc.).
