template decimal_to_decimal_array(array_len)
{
       signal input in;
       signal output out[array_len];
       
       signal temp[array_len];

       for (var i = 0; i< array_len; i++)
       {
           temp[i] <-- 10**(array_len-i-1);
           log(temp[i]);
       }
    

for (var i =0 ; i< array_len;i++)

{   
  if (i > 0) {
            out[i] <-- in / temp[i - 1] % 10;
        } else {
            out[i] <-- in / temp[i] % 10;
        }
        log(out[i]);
  log(out[i]);
}

}



component main { public[in] } = decimal_to_decimal_array(3);