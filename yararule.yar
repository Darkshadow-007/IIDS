rule testingrule{

    meta:
        author = "testingbuddy"
        Description = "testing the logs"
        hash = ""
    strings:
            $a = "192.168.100.3"
            $b = "CAXndF4wEC1bD1Flta"
            $c = "c732a3f4e03b8a93022ab307866af3cc0a985a3721dc28b50301f4486985641e"
    condition:
            ($a or $b or $c)
}
