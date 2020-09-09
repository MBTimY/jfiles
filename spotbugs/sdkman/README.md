This folder contains a vendored version of the SDKMAN installation script, so
that we can diff it when new versions are released. New versions will break our pipeline
because the `docker build` will fail checksumming the file downloaded. To
upgrade, download the new file, diff it with the local `sdkman.sh`, double check
the changes, and then only update `sdkman.sha1sum`.

Note: This is until https://gitlab.com/gitlab-org/gitlab/-/issues/219167 is done
