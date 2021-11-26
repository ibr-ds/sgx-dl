char *__data[] = {
		"first",
		"second",
		"third"
};

void *fct_datarel_access_first(void* args)
{
	(void)args;
	return (void*)__data[0];
}