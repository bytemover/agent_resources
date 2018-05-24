import "hash"

rule find_osqueryctl {
    condition:
        hash.md5(0, filesize) == "ae2fd3b678a151cc6b43d55a182dec00"
}

