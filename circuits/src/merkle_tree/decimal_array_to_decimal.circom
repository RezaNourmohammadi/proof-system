template decimal_array_to_decimal(array_len)
{
signal input in[array_len];
signal output out;
signal temp;

for(var i =0; i <array_len;i++)
{
    temp <-- in[i]*10**(array_len-i-1);
 out <-- temp+out;

}

log(out);
}

component main { public[in]} = decimal_array_to_decimal(10);