function toggleFirst() {
  let alldetails = document.querySelectorAll(".users pre > details");
  console.log(alldetails);
  let do_open = true;
  if (alldetails[0].open) {
    do_open = false;
  }
  alldetails.forEach((d) => {
    d.open = do_open;
  });
}
