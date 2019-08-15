# fame_modules

Community modules for FAME.

This repository is automatically added to all FAME installations.

You can get more information (and screenshots !) about FAME on the [website](https://certsocietegenerale.github.io/fame) and in the [documentation](https://fame.readthedocs.io/).

# Creating Docker-based modules

If you want to create Docker-based modules, please consider the following recommendations:
* When mounting your sample, just mount your `fame_config.temp_dir` or `fame-share` docker volume so that handling your sample in the Docker container is independent from your FAME installation (host-based or Docker-based)
* When mounting your sample, please ensure that you place the `output` directory **next** to your sample so that it does not interfere with any other analyses
* Create a fresh (and preferably random) folder for your sample and copy it to that folder (**note:** `temp_volume(target)` takes care of this and you are strongly encouraged to use it)
* Create a `build.sh` which builds your docker container
* Create a `install.sh` which installs all required system packages
    * *hint: you might want to call `build.sh` from within `install.sh` to have your container built at initialization time*
* Create a `requirements.txt` if you need additional Python packages for your module

You may want to take the existing Docker-based modules as a source of inspiration for creating your own module. This also should clarify some of the recommendations made above.

## Remarks

The starting point for APKPlugins was the [maldrolyzer](https://github.com/maldroid/maldrolyzer) project, using an MIT license.
