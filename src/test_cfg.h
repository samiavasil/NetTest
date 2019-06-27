#if defined(CONTEXT_CREATION)
#define ADD_TEST(tid, descr, r_nodes, hnd)     int nodes_##tid[r_nodes];

#elif defined(TEST_DESCRIPTORS)
#define ADD_TEST(tid, descr, r_nodes, hnd)  { \
                                            .context = { \
		                                    .t_id = tid, \
											.nodes = nodes_##tid, \
											.required_nodes = r_nodes, \
											.desc = descr \
                                             }, \
                                             .hndl = hnd \
                                             },


#endif


ADD_TEST(1,   "Test ping in normal receive mode", 2, test1)
ADD_TEST(2,  "Test ping in promiscuous receive mode", 2, test2)
ADD_TEST(3,  "Test multicast sniff in normal receive mode", 2, test3)
ADD_TEST(4, "Test multicast sniff in all multicast receive mode", 2, test4)

#undef CONTEXT_CREATION
#undef TEST_DESCRIPTORS
#undef ADD_TEST
