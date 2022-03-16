# pintool
Pintool to detect Overflow attacks in C

Steps to Execute:-
 1. make
 2. To run the attacks in testcases
 
    cd testcases
    
    cd attacks
    
    ./run.sh
    
 3. To run the benign in testcases
   
    cd testcases
    
    cd benign
    
    ./run.sh
    
In this project I have Monitored user inputs and marked it as tainted in the UT_Hash which are Fgets, gets and argv
Monitored the  string operations such as strcpy, strcat and checked if the source address of it is tainted (propagated from a user input) and marked the destination address as tainted if the source as well is tainted. 
For tracing the propagation of the tainted byte, I have added the source bytes to the UT_Hash of each tainted byte.
Monitored the return and jump instructions and checked if the target address is tainted. 
If the address of the return is tainted, terminate the program but before that raise an alarm and print the stack traces.
To get the stack traces, I have maintained a vector called StackTrace. I have checked if the instruction is a call or a return using INS_IsRet and INS_IsCall. To get the correct addresses, I have checked the image is valid and is a main executable. If it satisfies all these then push the address to the vector. If there is a Is_Ret, pop an address from the vector.
To get stack traces of each tainted byte, I have pushed the StackTrace vector to the UT_Hash of each tainted byte.
