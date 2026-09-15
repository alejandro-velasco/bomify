## bomify completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	bomify completion fish | source

To load completions for every new session, execute once:

	bomify completion fish > ~/.config/fish/completions/bomify.fish

You will need to start a new shell for this setup to take effect.


```
bomify completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify completion](bomify_completion.md)	 - Generate the autocompletion script for the specified shell

