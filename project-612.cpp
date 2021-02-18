#include "jansson.h"
#include "fann-test-app.hpp"

using namespace FANN;
neural_net *newANN;

int main(int argc, char *argv[])
{
    const float desired_error=0.001;
    const unsigned int max_epochs=100000;
    const unsigned int epochs_between_reports=5000;

    unsigned int num_layers=4;
    unsigned int num_input=10;
    unsigned int num_hidden=3;
    unsigned int num_output=1;

    training_data trdata;
    trdata.read_train_from_file("/home/alex/fann-master/datasets/abelone.train");

    fprintf(stdout, "%f\n", trdata.get_input()[0][2]);
    fprintf(stdout, "%f\n", trdata.get_output()[0][0]);

    trdata.shuffle_train_data();

    fprintf(stdout, "%f\n", trdata.get_input()[0][2]);
    fprintf(stdout, "%f\n", trdata.get_output()[0][0]);

    //fann_type indat[32][num_input], outdat[32][num_output];
    //trdata.set_train_data(32, num_input, (fann_type **)indat, num_output, (fann_type **)outdat);

    newANN=new neural_net;

    if(!newANN->create_from_file("/home/alex/abelone2.net"))
    {
        fprintf(stderr, "have no saved net. new net will be created now.\n");
        newANN->create_standard(num_layers, num_input, num_hidden, num_hidden, num_output);

        newANN->set_activation_function_hidden(SIGMOID_SYMMETRIC);
        newANN->set_activation_function_output(SIGMOID_SYMMETRIC);

        //newANN->set_activation_steepness_hidden(0.5);
        //newANN->set_activation_steepness_output(0.5);

        //printf("%f<=\n", newANN->get_activation_steepness(1,1));
        //printf("%f<=\n", newANN->get_activation_steepness(2,1));

        newANN->init_weights(trdata);
        //newANN->randomize_weights(-0.2, 0.2);
    }

    newANN->train_on_data(trdata, max_epochs, epochs_between_reports, desired_error);

    newANN->save("/home/alex/abelone.net");
/*
    printf("Testing network\n.");
    for(unsigned int i=0; i < trdata.length_train_data(); i++)
    {
        // Run the network on the test data
        fann_type *calc_out=newANN->run(trdata.get_input()[i]);

        printf("test ( ");
        for(unsigned int inpd=0; inpd<num_input; inpd++)
        {
            printf("%lf ", trdata.get_input()[i][inpd]);
        }
        printf(")-> %lf", *calc_out);

        printf(", should be %lf\n", trdata.get_output()[i][0]);
    }
*/
    newANN->destroy();

    return 0;
}
