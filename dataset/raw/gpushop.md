# Gpushop

desecription: Hey kid, wanna buy some gpus?  
Attachment: https://bit.ly/3jOft6u  
Challenge_Link: http://gpushop.2021.ctfcompetition.com , https://paymeflare-
web.2021.ctfcompetition.com/

# Source_Code  
By looking the Source Code, We knew that website is using the nginx server and
Laravel-php-framework version.

# Get_Hint

I am looking source code trying some sql attacks. And i go back to challenge
page. and decide to look closer to another web page.  
It was paymeflare. In the Documentation (https://paymeflare-
web.2021.ctfcompetition.com/doc), It was explain that how the challenge
website is working and what happen when we buy or checkout something from
products.

# Key Point  
Reading the lines, i understood. As he said "Any request with a path matching
(/checkout) will have an (X-Wallet header) added with the (payment address)."  
Remember that when we checkout the product, the website ask us to add our
address.  
So that mean when we checkout the product, there will be a (X-Wallet header)
with the (payment address).  
So our goal is to find the way how we can get rid of this header. But the
problem is every time when you check out the product, there will be (X-Wallet
header with address.)

# Thinking about solution  
To solve this problem, we need to change the url path. So i tried with many
things like changing the (/cart/checkout) to (/carT/CHECKOUT). But failed.  
After testing while, i knew that we can only change the (/checkout) not
(/cart). After while my good friend told me to try with (url encoding). So I
tried. and Got success

# Final_Solution  
I encoded the (checkout) to url (%63%68%65%63%6b%6f%75%74). and I send this
request. I Check my order, And There is a flag. Awesome! Really Nice
challenge.

# Get_Flag Request  
POST /cart/%63%68%65%63%6b%6f%75%74 HTTP/1.1  
Host: gpushop.2021.ctfcompetition.com

# Flag  
CTF{fdc990bd13fa3a0e760a14b560dd658c}

# Sorry  
I can't post and upload image here right now because of my github problems.
Please Forgive me. I will try my best to put image here.  

Original writeup
(https://github.com/ComdeyOverFlow/Google_CTF_2021/blob/main/gpushop.md).