package main

import (
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "os"
    "io/ioutil"
    "strings"
    "flag"
    "sync"
    "bufio"
)


var (
    tokenfile = flag.String("token", "", "A file containing the JWToken to crack.")
    wordlistfile = flag.String("wordlist", "", "The wordlist to use.")
    threads = flag.Int("t",10,"Threads to use")
    verbose = flag.Bool("v",false,"Print failed attempts.")
)

/*
 * Used to determine what to print
 * and if execution should stop.
 */
type Result struct {
    Message string      // Message to print
    Exit    bool        // Exit ?
}


/*
 * Prints the awesome raccoon banner.
 */

func init(){
    banner := `

                                .*/.
                               *((((*
                               /(((((*.
                               */*,...

                                                  .////*.
                                               .*//,...,/*
                                              ..       .//.
                        *//,.                          ,//.
                        .*(.   **.                     ((.
                              .(/.                   .*/.
                            .*/////*/*,.            .**
                               ..  .,(((*,.
                        ..   .*,.**    /(((*.
                   *,..*(/.    ,**.    ./((((*.
                   /(((((/               ./((((
                   /((((((*               .((((*.
                     .*(((((*,...           ./(*.
                         .//////**,,,,        .

                 JWT Cracking tool by 'CyberTrashPanda'

    ` + "\n"
    fmt.Printf(banner)
}


/*
 * Checks the error code.
 * If it is not 'nil' it
 * prints the error and exits.
 */

func handle(e error){
    if(e != nil){
        fmt.Println("[-] Error: ",string(e.Error()))
        os.Exit(1)
    }
}

/*
 * Checks if arguments are set
 */

func check_args(tokenfile string, wordlistfile string){
    if (tokenfile == "" || wordlistfile == ""){
        flag.PrintDefaults()
        os.Exit(1)
    }
}

/*
 * Just opens our file.
 * -----------------------------------------
 * returns a os.File pointer to the wordlist.
 */

func read_wordlist(filename string) *os.File{
    f,_err := os.Open(filename)
    handle(_err)
    return f
}

/*
 * Opens our token file, and reads the token.
 * ------------------------------------------
 * returns a string that is the token.
 */

func read_token(filename string) string {
    data, _err := ioutil.ReadFile(filename)
    handle(_err)
    return strings.Split(string(data), "\n")[0]
}

/*
 * Reads a password string from the wordlist ('wordc') channel.
 * It then tries to crack the token with it.
 */

func cracker(token string, wordc chan string, resc_chan chan <-Result, wg *sync.WaitGroup){
    for {
        word := <-wordc
        if(word == ""){
            break
        }
        resc_chan <- crack_token(token, []byte(word))
    }
    wg.Done()
}

/*
 * Reads each line from our wordlist file
 * and sends it to our wordlist channel.
 */

func scanner(f *os.File, wordc chan string){
    scanner := bufio.NewScanner(f)
    for scanner.Scan(){
        wordc <-scanner.Text()
    }
}

/*
 * Iterates over our channel data and
 * just prints our results.
 */

func printer(resc chan Result, verbose bool){
    for r:= range resc {
        print_result(r,verbose)
    }
}

/*
 * This is the function that prints
 * our message and decides if it's time
 * to stop execution.
 */

func print_result(res Result, verbose bool){
    if(res.Exit == true){
        fmt.Printf(res.Message)
        os.Exit(1)
    }
    if(verbose == true && res.Exit == false){
        fmt.Printf(res.Message)
    }
}

/*
 * Parses our token with the given password
 * if the result token is valid, we cracked it.
 * Note: I am not checking for expired sessions.
 * ---------------------------------------------
 * returns our Result struct.
 */

func crack_token(token_string string, password []byte) Result{
    var res Result
    token,_ := jwt.Parse(token_string, func(token *jwt.Token)(interface{}, error){
        return password, nil
    })

    if(token.Valid){
            res.Message = fmt.Sprintf("[+] Cracked JWT with secret-key '%s'\n", string(password))
            res.Exit = true
    }else{
        res.Message = fmt.Sprintf("[-] Failed with secret-key '%s'\n", string(password))
        res.Exit = false
    }

    return res
}


/*
 * It prepares our "threads" or goroutines
 * to be precise, channels etc.
 * Then waits for all of them to finish.
 */

func main(){
    var token string
    var wordlist *os.File
    var c int
    var wg sync.WaitGroup

    flag.Parse()

    if(*threads < 1){
        *threads = 1
    }

    check_args(*tokenfile,*wordlistfile)
    token = read_token(*tokenfile)
    wordlist = read_wordlist(*wordlistfile)

    wordc := make(chan string, *threads)
    resc := make(chan Result)

    wg.Add(*threads)

    go scanner(wordlist, wordc)
    for c = 0; c < *threads; c++ {
        go cracker(token, wordc, resc, &wg)
    }
    go printer(resc,*verbose)

    wg.Wait()
}
