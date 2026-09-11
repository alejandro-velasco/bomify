## bomify completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(bomify completion bash)

To load completions for every new session, execute once:

#### Linux:

	bomify completion bash > /etc/bash_completion.d/bomify

#### macOS:

	bomify completion bash > $(brew --prefix)/etc/bash_completion.d/bomify

You will need to start a new shell for this setup to take effect.


```
bomify completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages) (default "C:\\Users\\aleja\\.bomify")
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify completion](bomify_completion.md)	 - Generate the autocompletion script for the specified shell

