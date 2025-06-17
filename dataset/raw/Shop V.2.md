Shop V.2  
========

Task description  
----------------

> Fixed some things http://shop2.q.2019.volgactf.ru

Solution  
--------

TL;DR: Mass assignment vulnerability through ModelAttribute in Spring Boot  
(using an array and a different setter name).

This tasks involves nearly the same shop application as in the shop task. The  
only difference is, that the `buy` method was disabled. We therefore only  
describe the differences in the exploit here and recommend to read the write-
up  
for shop first.

In the robots.txt you will find `Disallow: /shop-1.0.1.war`, which gives your  
nearly the same source code, except for the `buy` method, which no longer can  
be used to buy products.

However, we are still left with the `profile` method:

   @Controller  
   public class ShopController {  
   // [...]  
       @RequestMapping({"/profile"})  
       public String profile(@ModelAttribute("user") User user, Model templateModel, HttpServletRequest request) {  
           HttpSession session = request.getSession();  
           if (session.getAttribute("user_id") == null) {  
               return "redirect:index";  
           } else {  
               List<Product> cart = new ArrayList();  
               user.getCartItems().forEach((p) -> {  
                   cart.add(this.productDao.geProduct(p.getId()));  
               });  
               templateModel.addAttribute("cart", cart);  
               return "profile";  
           }  
       }

We find the same ModelAttribute annotation on the user variable. However,  
while we can change the `balance` attribute, is has only an effect on the  
rendered template, since the changes on user are not written to the database.  
Additionally, we cannot buy anything, so having many monetary units provides  
not benefit. However, there is another interesting attribute: `cart`. We could  
put the flag product in our cart and display it on the profile (without  
actually posessing it). The methods reads all products in our cart from the  
database again, so we will receive the flag once we have a product in our cart  
with a `productId` of 4.

The `cart` attribute is of type `List[Product]`, so it is not only a scalar  
value, but a more complex structure. After some search on how Spring Boot  
handles such values in form data, we found the correct way of encoding lists  
with objects: `cart[0].id`, `cart[0].title`, and so on. So we appended those  
field names to the URL, setting `cart[0].id = 4`. This resulted in an “HTTP
400  
Bad Request”. Turns out that the browser does not encode them properly when  
you just append them to the URL in the URL bar. So we create a simple HTML
form  
to craft the request. While the request was processed correctly, we did not  
find the flag in our cart. Taking a closer look, you will find that the user  
models defines a setter `setCartItems` instead of `setCart`. So changing the  
field names to `cartItems[0].id`, `cartItems[0].title` etc., results in the  
flag `VolgaCTF{e86007271413cc1ac563c6eca0e12b62}` being shown on the profile.

Original writeup
(https://github.com/b4ckspace/ctfwriteups/tree/master/2019.03%20VolgaCTF%20Qualifiers/shopv2).