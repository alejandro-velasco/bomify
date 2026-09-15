## bomify completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(bomify completion zsh)

To load completions for every new session, execute once:

#### Linux:

	bomify completion zsh > "${fpath[1]}/_bomify"

#### macOS:

	bomify completion zsh > $(brew --prefix)/share/zsh/site-functions/_bomify

You will need to start a new shell for this setup to take effect.


```
bomify completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

