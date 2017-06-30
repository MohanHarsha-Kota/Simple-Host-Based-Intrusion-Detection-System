/*
 * Simple Java Regular Expression based tool to analyse web server log files.
 * Detects suspicious requests and also finds the top 10 computers making requests.
 * Uncomment one function at a time to get the result of each function.
 * Done in NetBeans IDE.
 * Dont forget to change the path to the log file.
 * No other depencies. Can be executed directly.
 * Done By Sai Mohan Harsha Kota
 * Contributions from Vamsi
 */
package javaapplication2;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class JavaApplication2 
{
    static int malicious(String data, String regex, int count) // All suspicious and potentially risk related requests
    {
       
        System.out.println(data);
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(data);
        while(m.find())
        {
            System.out.println("The above request appears to be an malicious attempt. Please verify!");
            count++;
        }
        System.out.println("--------------------------------------");
        return count;
        
    }
    static int cgibinattacks(String data, String regex, int count) // cgi files probe detector
    {
        System.out.println(data);
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(data);
        while(m.find())
        {
            System.out.println("The above request appears to be a Cgi-bin Attack. Please verify!");
            count++;
        }
        System.out.println("--------------------------------------");
        return count;
    }
    static int pathaccessattacks(String data, String regex, int count) // cgi file access attemots detector
    {
        System.out.println(data);
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(data);
        while(m.find())
        {
            System.out.println("The above request appears to be a pathaccess Attack. Please verify!");
            count++;
        }
        System.out.println("--------------------------------------");
        return count;
    }
    static int scriptattacks(String data, String regex, int count) // executable scripts 
    {
        System.out.println(data);
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(data);
        while(m.find())
        {
            System.out.println("The above request appears to execute a script or file. Please verify!");
            count++;
        }
        System.out.println("--------------------------------------");
        return count;
    }
    static int directorytraversalattacks(String data, int count) // directory traversal attack detector 
    {
        System.out.println(data);
        String unicode = "../";
        String[] DataParts = data.split("\\s+");
        String Reqname = DataParts[4];
        System.out.println(Reqname);
            if(Reqname.indexOf(unicode)!=-1)
            {
                System.out.println("The above request appears to go up in the directory, Please verify!");
                count++;
            } 
        
        System.out.println("--------------------------------------");
        return count;
    }
    static int xssattacks(String data, String regex, int count) // xss attack detector
    {
        System.out.println(data);
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(data);
        while(m.find())
        {
            System.out.println("The above request appears to be a XSS Attack. Please verify!");
            count++;
        }
        System.out.println("--------------------------------------");
        return count;
    }
    
    static int sqlinjectionattacks(String data, String regex, int count) // Sql injection attack detector
    {
        System.out.println(data);
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(data);
        while(m.find())
        {
            System.out.println("The above request appears to be a sqlinjection Attack. Please verify!");
            count++;
        }
        System.out.println("--------------------------------------");
        return count;
    }
    
    static void otherreqanalysis(String otherclientnames) // Analysis of the requests other than top 10 clients
    {
        try
        {
            int l =0, i = 0, j =0,k=0, h =0,o=0,f=0, n = 0;
            String file ="C:\\Users\\HARSHA KOTA\\Documents\\NetBeansProjects\\JavaApplication4\\src\\javaapplication4\\access-log.txt";
            BufferedReader obj = new BufferedReader(new FileReader(file));
            String entry;
            while(( (entry = obj.readLine())!= null) )
            {
                    if (entry.toLowerCase().indexOf(otherclientnames)==-1)
                    {
                        String[] DataParts = entry.split("\\s+");
                        String Reqname = DataParts[4];
                        String[] ReqParts = Reqname.split("/\\/+/g");
                        l = ReqParts.length;
                        String Request = ReqParts[l-1];
                        if(Request.toLowerCase().indexOf(".shtml")!=-1)
                        {
                            n+=1;
                        }
                        else if(Request.toLowerCase().indexOf(".htm")!=-1)
                        {
                            i+=1;
                        }
                        else if(Request.toLowerCase().indexOf(".pdf")!=-1)    
                        {
                            j+=1;
                        }
                        else if(Request.toLowerCase().indexOf(".cgi")!=-1)
                        {
                            k+=1;
                        }
                        else  if(Request.toLowerCase().indexOf(".pl")!=-1||Request.toLowerCase().indexOf(".exe")!=-1||Request.toLowerCase().indexOf(".dat")!=-1)
                        {
                            h+=1;
                        }
                        else if (Request.toLowerCase().indexOf(".jpg")!=-1||Request.toLowerCase().indexOf(".gif")!=-1||Request.toLowerCase().indexOf(".jpeg")!=-1)
                        {
                            o+=1;
                        }
                        else
                        {
                            f+=1;
                        }
                   }
            }
            System.out.println("------------------------------------------");
            System.out.println("Pages Requested by other than Top 10 clients are:" );
            System.out.println("shtml page Requests are: "+n);
            System.out.println("Html page Requests are: "+i);
            System.out.println("Pdf page Requests are: "+j);
            System.out.println(".Cgi page Requests are: "+k);
            System.out.println("Executable script page Requests are: "+h);
            System.out.println("Images Requests are: "+o);
            System.out.println("Other Requests are: "+f);
            System.out.println("------------------------------------------");
        }
        catch(IOException e)
        {
            System.err.println(e.getMessage());
        }
    }
    static void topreqanalysis(String topclientname) // Function to examine the requests of top 10 clients.
    {
         try
        {
            int l =0, i = 0, j =0,k=0, h =0,o=0,f=0, n = 0;
            String file ="C:\\Users\\HARSHA KOTA\\Documents\\NetBeansProjects\\JavaApplication4\\src\\javaapplication4\\access-log.txt";
            BufferedReader obj = new BufferedReader(new FileReader(file));
            String entry;
            while((entry = obj.readLine())!= null)
            {
                
                if(entry.toLowerCase().indexOf(topclientname)!=-1)
                {
                    String[] DataParts = entry.split("\\s+"); 
                   
                    String Reqname = DataParts[4];
                    String[] ReqParts = Reqname.split("/\\/+/g");
                    l = ReqParts.length;
                    String Request = ReqParts[l-1]; // now splitting the request URL to see whether it is a html page request or pdf ,etc.
                    if(Request.toLowerCase().indexOf(".shtml")!=-1)
                    {
                        n+=1;
                    }
                    if(Request.toLowerCase().indexOf(".htm")!=-1)
                    {
                        i+=1;
                    }
                    else if(Request.toLowerCase().indexOf(".pdf")!=-1)    
                    {
                        j+=1;
                    }
                    else if(Request.toLowerCase().indexOf(".cgi")!=-1)
                    {
                        k+=1;
                    }
                    else  if(Request.toLowerCase().indexOf(".pl")!=-1||Request.toLowerCase().indexOf(".exe")!=-1||Request.toLowerCase().indexOf(".dat")!=-1)
                    {
                        h+=1;
                    }
                    else if (Request.toLowerCase().indexOf(".jpg")!=-1||Request.toLowerCase().indexOf(".gif")!=-1||Request.toLowerCase().indexOf(".jpeg")!=-1)
                    {
                        o+=1;
                    }
                    else
                    {
                        f+=1;
                    }
                }   
            }
            System.out.println("------------------------------------------"); // Summary of the requests
            System.out.println("Pages Requested by "+topclientname+" are:" );
            System.out.println("shtml page Requests are: "+n);
            System.out.println("Html page Requests are: "+i);
            System.out.println("Pdf page Requests are: "+j);
            System.out.println(".Cgi page Requests are: "+k);
            System.out.println("Executable script page Requests are: "+h);
            System.out.println("Images Requests are: "+o);
            System.out.println("Other Requests are: "+f);
            System.out.println("------------------------------------------");
        }
        catch(IOException e)
        {
         System.err.println(e.getMessage());
        }
    }
    
    static void topclients() // Function to find the total number of clients and sort them to find the top 10
    {
        HashMap<String,Integer> clientnames = new HashMap<String,Integer>();        // using hashmaps to map the names of the client as key and their count as value
        String regex = "\\s+";
        try
        {
            String file ="C:\\Users\\HARSHA KOTA\\Documents\\NetBeansProjects\\JavaApplication4\\src\\javaapplication4\\access-log.txt";
            BufferedReader obj = new BufferedReader(new FileReader(file));
            String entry;
            while((entry = obj.readLine())!= null)
            {
                String[] DataParts = entry.split(regex);
                String Cname = DataParts[2]; // Splitting the entry in the log to grab the client name section
                if(clientnames.containsKey(Cname))   // populating the list
                {
                    clientnames.put(Cname, clientnames.get(Cname) + 1);
                }else
                {
                    clientnames.put(Cname, 1);
                }
            }
           
        }
        catch(IOException e)
        {
         System.err.println(e.getMessage());
        }
        List<Map.Entry<String,Integer>> Allclients = new LinkedList<Map.Entry<String,Integer>>(clientnames.entrySet());
        Collections.sort(Allclients, new Comparator<Map.Entry<String,Integer>>() // Comparing the clients to create an ordered list
        {
            public int compare(Map.Entry<String, Integer> n1, Map.Entry<String, Integer> n2) {
                return (n2.getValue()).compareTo(n1.getValue());
            }
        });
        System.out.println("Top 10 Client Computers making requests are:");
        for(int i=0;i<10;i++) // Printing the top 10 clients
        {
            String TopClients = Allclients.get(i).getKey();
            int Totalrequests = Allclients.get(i).getValue();   
            System.out.println(i+1 + " Name:" +TopClients+ "Requests made:" +Totalrequests);
        }
        for(int i=0;i<10;i++)
        {
           topreqanalysis(Allclients.get(i).getKey());  
        }
        System.out.println(Allclients.size());
        for (int i = 0;i<10;i++)
        {
            otherreqanalysis(Allclients.get(i).getKey());
        }
    }
    
    public static void main(String[] args) throws IOException
    {
        // Various Regular Expressions to detect various kinds of attack.
        String Q2 = "^[0-9-]+\\s[0-9.]+\\s[A-Za-z0-9-\\/.]+\\s[\"A-Z]+\\s[A-Za-z0-9\\/~.-_?=&]+\\s[A-Z\\/0-9\".]+\\s([404]+|[403]+|[401]+|[400]+|[508]+|[429]+)\\s\\d+";
        String Q3_cgibin_attacks = "^[0-9\\s.-]+[A-Z0-9a-z-.]+\\s[A-Z\"]+\\s([.~_=?&-\\/\\w+]*\\b([cgi]+[\\-]+[bin]+)\\b[.~_=?&-\\/\\w+]*)\\s[A-Z\\/0-9.\"]+\\s([404]+|[403]+|[401]+)\\s\\d+";
        String Q3_pathaccess_attacks = "^[0-9\\s.-]+[A-Z0-9a-z-.]+\\s[A-Z\"]+\\s[A-Z\\/a-z-_=~]+([.cgi]+)\\s[A-Z\\/0-9.\"]+\\s[403|401|404]+\\s\\d+";
        String Q3_script_attacks = "^[0-9-.\\s]+[\"A-Z]+\\s[-_A-Za-z0-9\\/|%|?|=|&]+([.pl]+|[.PL]+|[.exe]+)\\s[A-Z\\/0-9\".]+\\s([401|403|404]+)\\s\\d+";
        String Q3_xssattack = "/((\\%3C)|<)((\\%69)|i|(\\%49))((\\%6D)|m|(\\%4D))((\\%67)|g|(\\%47))[^\\n]+((\\%3E)|>)/I";
        String Q3_sqlattacks = "/\\w*((\\%27)|(\\'))(\\s|\\+|\\%20)*((\\%6F)|o|(\\%4F))((\\%72)|r|(\\%52))/ix";
        try
        {
            FileReader file = new FileReader("C:/Users/HARSHA KOTA/Desktop/lab2-access-log.txt"); // Redading the log file
            BufferedReader obj = new BufferedReader(file);
            String text = "";
            String entry = obj.readLine();
            int a = 0, b = 0, c = 0, d = 0, e = 0, f = 0,g = 0;   // Variables to calculate the count of the respective attacks.
            while(entry!= null)
            {
                text += entry; 
                entry = obj.readLine();
                                                            // Uncomment one function call at a time.
                a = malicious(text,Q2,a);
                //b = cgibinattacks(text,Q3_cgibin_attacks,b);
                //c = pathaccessattacks(text,Q3_pathaccess_attacks,c);
                //d = scriptattacks(text,Q3_script_attacks,d);
                //e = xssattacks(text, Q3_xssattack, e);
                //f = sqlinjectionattacks(text, Q3_sqlattacks,f);
                //g = directorytraversalattacks(text,g);
                text = "";
            }
            System.out.println("Total Malicious Attempts are: "+a);
            //System.out.println("Total Cgin-bin Attacks are: "+b);
            //System.out.println("Total Path Access Attacks are: "+c);
            //System.out.println("Total Attacks to execute files are: "+d);
            //System.out.println("Total XSS attacks are: "+e);
            //System.out.println("Total Sql Injection attaempts are: "+f);
            //System.out.println("Total Directory traversal Attacks are: "+g);
            System.out.println("-------------------------------------");
            //topclients();
            System.out.println("-------------------------------------");
            
        }
        catch (IOException e)
        {
            System.err.println(e.getMessage());
        }
    }
}
