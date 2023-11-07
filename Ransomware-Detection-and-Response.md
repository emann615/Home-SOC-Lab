
I followed Eric Stubacks’s SOC lab guide to:
-	Create an attacker VM (Ubuntu) & victim VM (Windows).
-	Disable Windows Defender on the victim machine.
-	Install Sysmon on victim machine.
-	Install Sliver Server on the attacker machine.
-	Create and deliver malicious payload to victim machine.
-	Create a Lima Charlie account and install a sensor on the victim machine.
-	Create my first detection and response rule and stop malicious activity.

## Preventing ransomware attack
-	The first rule I created was to prevent ransomware that uses the `vssadmin delete shadows /all`
o	Vssadmin is a default Windows process that controls volume shadow duplicates of the documents on a given PC. These shadow copies are regularly utilized as a recovery point, and they can be utilized to reestablish or return the file to a past state if they are destroyed or lost due to some reasons.
-	The first rule I created was the following:
o	
-	The rule is good for stopping ransomware that uses the exact command but will not stop any ransomware that has modified the command even slightly.
o	Ex:
-	To test this out I downloaded a ransomware simulator.
o	It uses the following command to delete shadow copies:
-	If I run the ransomware executable and check detections in Lima Charlie, I can see that my rule was not triggered:

## Using the Contains Operator
-	I modified the rule to use the contains operator.
o	Now the rule will trigger for any command that include the values “vssadmin”, “delete”, “shadows” and “/all”.
-	When I ran the ransomware executable again, I could see that the rule was triggered in Lima Charlie and the attack was stopped.
-	The rule did work, but it still leaves the victim machine open to other methods for deleting shadow copies that could be used by ransomware.
-	To demonstrate this, I edited the source code of the ransomware to use a different method of deleting shadow copies.
-	I executed the ransomware again.
-	This time the ransomware was able to complete its attack by resizing the shadowstorage and encrypting files on my Windows VM.

## Making the Rule More Robust
-	I wanted to see if I could make my rule robust to trigger for multiple different methods that could be used by ransomware to delete shadow copies.
-	I modified the rule to include other methods that could be used to delete shadow copies.
-	I ran the ransomware executable again and my rule was successfully triggered.
