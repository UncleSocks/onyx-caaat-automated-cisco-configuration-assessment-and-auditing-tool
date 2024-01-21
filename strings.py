

def logo():

    caaat_logo = """                                                                         
==================================================================================================================                                                                                      
==================================================================================================================                                                                                          
          :;       ..    _______                                                         
            +X$XxxX$x    < MEOW >                                                          
            X$$$XXX+    [_______]                                                      
            :$$X$xX$:   /                                                          
        .;$X$$$X$$$                                                               
      :X$$X$$$$XXx;+                                                               
    :XX$$$$$$$$$&$XX                                                               
  .XXX$$$$$XXX$&&$.                                                               
  xXXX$$$$$XX$&$;   +$&+ &&X.  .;&&&&&+  ;&&;.$&&&&&.  ;&$. :&&&&&x. ;&$:         
  x$$X$$$&$X$$$+  :&&&&. $&&&X   x$&&&&X  ..   X&&&&$   :    .&&&&&+ :;           
  ;$$$$$$$$$$$$   &&&&&. $&&&&x  x +&&&&&..     X&&&&$::      .&&&&&x             
  .$$$$$$$$$$$X  .&&&&&. $&&&&X  x  .&&&&&X      x&&&&+        .&&&&&;            
  .X$$$$$$$$$$x   $&&&&. $&&&&.  x    $&&&&      ;&&&&+       :.:&&&&&:           
  ;$$$$$$$$$$$$$$.  +&&&. $&&&.  .&.    +&&&      ;&&&&+      $:  .&&&&&:          
  ;$$X.   ....XX:     ......     ..    ....      ......      ..  .......  , iii, iv, v                                     
    X$$$Xxxx+xX                                                                    
        .:;x;           Cisco Another Automated Assessment Tool  

                                                                                  
Created by Tyrone Kevin Ilisan (@unclesocks)

[+] Release 2023.1.0
[+] Audits CIS Cisco IOS 15 and IOS 17 Benchmarks version 8
[+] Supports HTML and CLI output

Tip: Use the -h option for more information on how to use Onyx's arguments and ensure stable connectivity between 
the target Cisco router and the host machine running the CAAAT.

GitHub: https[://]github[.]com/UncleSocks/onyx-caaat

==================================================================================================================                                                                       
    """

    return print(caaat_logo)


def onyx_description():
    
  onyx_description = """
Onyx is an automated assessment tool, currently supporting Center for Internet Security (CIS) Cisco IOS 15 Benchmark
and Cisco IOS 17 Benchmark version 8. If no option is specified, it will automatically attempt to identify the Cisco
IOS version and will only output the assessment result in the CLI.
  """

  return onyx_description


def onyx_epilog():
   
   onyx_epilog = """
The HTML report output is saved under the 'reports_module' directory.
    """
   
   return onyx_epilog