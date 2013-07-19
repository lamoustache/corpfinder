corpfinder
==========

"You don' understand wha he want yo! Da man sayz he want to pwn'em. He needs them IPs and a burner laptop for da operationz! You know nothin' fool!"

Simple script that "try" to return a list of netblock belonging to a given company name. It uses WHOIS primary/inverse queries and some magic voodoo to search for potential candidates.

    ./corpfinder -s "company name"
    
Some WHOIS databases have daily limit consider using torify to avoid blocking.

TODO
----

* include debug 
* clean the code
* add search criteria
* add options to display extra information (country, hosting provider etc.)
* have output format (JSON, XML, CSV etc.)
* parse IPv6 result

    

 
