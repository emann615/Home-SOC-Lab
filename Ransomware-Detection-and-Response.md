
I followed Eric Stubacks’s SOC lab guide to:
- Create an attacker VM (Ubuntu) & victim VM (Windows).
- Disable Windows Defender on the victim machine.
- Install Sysmon on victim machine.
- Install Sliver Server on the attacker machine.
- Create and deliver malicious payload to victim machine.
- Create a Lima Charlie account and install a sensor on the victim machine.
- Create my first detection and response rule and stop malicious activity.

## Preventing ransomware attack
- The first rule I created was to prevent ransomware that uses the `vssadmin delete shadows /all`
    - Vssadmin is a default Windows process that controls volume shadow duplicates of the documents on a given PC. These shadow copies are regularly utilized as a recovery point, and they can be utilized to reestablish or return the file to a past state if they are destroyed or lost due to some reasons. Ransomware programs use this process to prevent victims from being able to recover their files.
-	The rule is as follows:
#### Detect
```
event: NEW_PROCESS
op: and
rules:
  - op: is
    path: event/FILE_PATH
    value: C:\Windows\system32\vssadmin.exe
  - op: is
    path: event/COMMAND_LINE
    value: '"C:\Windows\system32\vssadmin.exe" delete shadows /all'
  - op: is
    path: routing/hostname
    value: desktop-jf9q90k.hsd1.tn.comcast.net
  ```
#### Respond
```
- action: report
  name: vss_deletion_kill_it
- action: task
  command:
    - deny_tree
    - <<routing/parent>>
```
- The rule is good for stopping ransomware that uses the exact command but will not stop any ransomware that has modified the command even slightly.
- To test this out I downloaded a ransomware simulator. It uses the command `vssadmin delete shadows /for=norealvolume /all /quiet` to delete shadow copies.
- When I ran the ransomware executable, I could see that it was allowed to complete and encrypt my files.
- When I checked the Detections tab in Lima Charlie, I could also see that my rule was not triggered.

## Using the Contains Operator
-	I modified the detect part of the rule to use the contains operator.
#### Detect
```
event: NEW_PROCESS
op: and
rules:
  - op: is
    path: event/FILE_PATH
    value: C:\Windows\system32\vssadmin.exe
  - op: contains
    path: event/COMMAND_LINE
    value: 'delete'
  - op: contains
    path: event/COMMAND_LINE
    value: 'shadows'
  - op: contains
    path: event/COMMAND_LINE
    value: '/all'
```
- This rule will trigger for any command that include the values “vssadmin”, “delete”, “shadows” and “/all”.
- When I ran the ransomware executable again, I could see that the rule was triggered in Lima Charlie and the attack was stopped.
- The rule did work, but it still leaves my Windows VM open to other methods of deleting shadow copies that could be used by ransomware.
- To demonstrate this, I edited the source code of the ransomware to use the command `vssadmin resize shadowstorage`.
- I executed the ransomware again. This time the ransomware was able to complete its attack by resizing the shadowstorage and encrypting files on my Windows VM.

## Making the Rule More Robust
- I wanted to see if I could make my rule robust to trigger for multiple different methods that could be used by ransomware to delete shadow copies.
- I modified the detect part of rule to include other methods of deleting shadow copies.
#### Detect
```
event: NEW_PROCESS
op: and
rules:
  - case sensitive: false
    op: matches
    path: event/FILE_PATH
    re: .*(vssadmin|wmic)\.exe$
  - op: or
    rules:
      - op: and
        rules:
          - op: contains
            path: event/COMMAND_LINE
            value: delete
          - op: contains
            path: event/COMMAND_LINE
            value: shadows
          - op: contains
            path: event/COMMAND_LINE
            value: /all
      - op: and
        rules:
          - op: contains
            path: event/COMMAND_LINE
            value: resize
          - op: contains
            path: event/COMMAND_LINE
            value: shadowstorage
      - op: and
        rules:
          - op: contains
            path: event/COMMAND_LINE
            value: shadowcopy
          - op: contains
            path: event/COMMAND_LINE
            value: delete
```
  
-	I ran the ransomware executable again and my rule was successfully triggered stopping the attack.
