### Algorithm: Sanitization Verifier (SV)

**Input:** CFG `G`, `UVO_DDG`, filter function `f`  
**Output:** Bug report

```
Function SV(G, UVO_DDG, f):

    if f is None OR f is buggy then
        Print("This program is vulnerable")
        if f is buggy then
            Print("and has buggy filter function", f)
        else
            Print("and has no filter function")
        return

    IsDetc ← False

    for each candidate_path in UVO_DDG do
        IsVuln ← True

        for each func in candidate_path do
            if func == f then
                IsVuln ← False
                IsDetc ← True
                // Data-dependency filter detected
                continue to next candidate_path

    if IsDetc == False then
        // Switch to CFG

        for each func in candidate_path do
            IsVuln ← True

            for each s in succ_func(G) do
                if s == f then
                    IsVuln ← False
                    IsDetc ← True
                    // Control-flow filter detected
                    continue to next s

        if IsVuln == True then
            Print("This is vulnerable path")

    if IsDetc == False then
        Print("This is vulnerable program")

    return
```
